# Gemini API Key Audit Script

This script audits your Google Cloud Organization to find projects where the Gemini API (Generative Language API) is enabled and checks for unrestricted API keys in those projects.

## Purpose

Unrestricted API keys pose a security risk as they can be used to access any enabled API in the project, potentially leading to billing spikes or data exposure if leaked. This script helps identify such keys in the context of Gemini API usage.

## Prerequisites

- **Google Cloud SDK (gcloud)** installed and authenticated.
- **jq** command-line JSON processor installed.
- **Cloud Asset API** (`cloudasset.googleapis.com`) enabled on the active project.
- Permissions to list organizations and assets at the organization level.

## Usage

1.  Ensure you are authenticated with gcloud:
    ```bash
    gcloud auth login
    ```
2.  Set your active project (where Cloud Asset API is enabled):
    ```bash
    gcloud config set project YOUR_PROJECT_ID
    ```
3.  Run the script:
    ```bash
    ./audit_gemini_keys.sh
    ```
    The script will attempt to auto-detect your Organization ID. If multiple are found or none, it will prompt you.

## Output

The script will output:
- Projects with Gemini API enabled.
- High-risk exposure detection for projects with unrestricted keys.
- A summary of all unrestricted API keys organization-wide.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
