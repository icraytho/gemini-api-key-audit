#!/bin/bash

if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is not installed. Please install it to parse JSON output."
    exit 1
fi

echo "Verifying prerequisites..."

# Verify the Cloud Asset API is enabled on the currently active project
CAI_CHECK=$(gcloud services list --enabled --filter="config.name:cloudasset.googleapis.com" --format="value(config.name)" 2>/dev/null)

if [ "$CAI_CHECK" != "cloudasset.googleapis.com" ]; then
  echo "❌ Error: The Cloud Asset API (cloudasset.googleapis.com) is not enabled on your active gcloud project, or no active project is set."
  echo "   Please set an active project and enable the API by running:"
  echo "     gcloud config set project YOUR_PROJECT_ID"
  echo "     gcloud services enable cloudasset.googleapis.com"
  exit 1
fi

echo "✅ Cloud Asset API is enabled."

# Attempt to auto-detect the Organization ID
echo "Detecting Organization ID..."
ORG_IDS=($(gcloud organizations list --format="value(ID)"))

if [ ${#ORG_IDS[@]} -eq 0 ]; then
  echo "⚠️  No Organizations found automatically."
  read -r -p "Please manually enter your Google Cloud Organization ID: " ORG_ID
elif [ ${#ORG_IDS[@]} -eq 1 ]; then
  ORG_ID=${ORG_IDS[0]}
  echo "✅ Detected Organization ID: $ORG_ID"
else
  echo "Multiple Organizations detected:"
  gcloud organizations list --format="table(ID, displayName)"
  read -r -p "Enter the specific Organization ID to audit: " ORG_ID
fi

if [ -z "$ORG_ID" ]; then
  echo "Error: Organization ID cannot be empty. Exiting."
  exit 1
fi

echo "Building Project ID mapping (to resolve raw project numbers)..."
PROJECT_MAP=$(gcloud projects list --format="json(projectNumber, projectId)" 2>/dev/null)
# Saftey fallback if the mapping fails so jq doesn't break
if [ -z "$PROJECT_MAP" ]; then PROJECT_MAP="[]"; fi

echo "Querying CAI for projects with the Gemini API enabled..."
echo "(This may take a moment depending on org size...)"

# 1. Fetch all projects with Gemini enabled. 
# This correctly returns the Project Number.
GEMINI_PROJECTS=$(gcloud asset search-all-resources \
  --scope="organizations/$ORG_ID" \
  --asset-types="serviceusage.googleapis.com/Service" \
  --query="state:ENABLED AND name:*generativelanguage.googleapis.com*" \
  --format="value(project)" 2>/dev/null | sed 's/projects\///')

if [ -z "$GEMINI_PROJECTS" ]; then
  echo "✅ No projects found with the Gemini API enabled. Audit complete."
  exit 0
fi

echo "Querying CAI for all API Keys across the organization..."
# 2. Fetch the full configuration of all API keys org-wide.
KEYS_JSON=$(gcloud asset list \
  --organization="$ORG_ID" \
  --asset-types="apikeys.googleapis.com/Key" \
  --content-type=resource \
  --format="json" 2>/dev/null)

if [ -z "$KEYS_JSON" ] || [ "$KEYS_JSON" = "[]" ]; then
  echo "✅ No API keys found in the organization. Audit complete."
  exit 0
fi

echo "============================================================="
echo "Analyzing risk intersections in memory..."

# 3. Iterate through the vulnerable projects and parse the JSON locally
for PROJECT in $GEMINI_PROJECTS; do
  
  # Translate Number to ID using the map we built earlier
  PROJECT_ID=$(echo "$PROJECT_MAP" | jq -r --arg pnum "$PROJECT" '.[] | select(.projectNumber == $pnum) | .projectId')
  PROJECT_ID=${PROJECT_ID:-$PROJECT} # Fallback to the number if the ID lookup fails
  
  # Use jq to extract keys that belong to this specific project AND lack 'apiTargets'
  PROJECT_KEYS=$(echo "$KEYS_JSON" | jq -r --arg proj "$PROJECT" '
    .[] | 
    select(.name | contains("/projects/" + $proj + "/")) | 
    select(.resource.data.restrictions.apiTargets == null) | 
    "        - \(.resource.data.displayName) (UID: \(.resource.data.uid))"
  ')

  if [ -n "$PROJECT_KEYS" ]; then
    echo -e "\n🚨 HIGH RISK EXPOSURE DETECTED in Project: $PROJECT_ID 🚨"
    echo "   [!] The Gemini API is ENABLED."
    echo "   [!] The following API Keys lack service restrictions:"
    echo "$PROJECT_KEYS"
  else
    echo "ℹ️  INFO: Project '$PROJECT_ID' has the Gemini API enabled, but no unrestricted keys found."
  fi

done

echo -e "\n============================================================="
echo "Audit: All Unrestricted API Keys Organization-Wide"
echo "============================================================="

# 4. Parse the in-memory JSON for ANY key missing apiTargets, regardless of project
# We pass the PROJECT_MAP into jq as an argument to translate numbers to IDs on the fly
ALL_UNRESTRICTED_KEYS=$(echo "$KEYS_JSON" | jq -r --argjson pmap "$PROJECT_MAP" '
  # Build a dictionary of { "123456": "my-project-id" }
  ($pmap | map({(.projectNumber): .projectId}) | add) as $dict |
  .[] | 
  select(.resource.data.restrictions.apiTargets == null) | 
  (.name | split("/")[4]) as $pnum |
  ($dict[$pnum] // $pnum) as $pid |
  "   - Project: \($pid) | Key: \(.resource.data.displayName) (UID: \(.resource.data.uid))"
')

if [ -n "$ALL_UNRESTRICTED_KEYS" ]; then
  echo "$ALL_UNRESTRICTED_KEYS"
else
  echo "✅  Excellent. No unrestricted API keys found anywhere in the organization."
fi

echo -e "\n============================================================="
echo "Audit Complete."
