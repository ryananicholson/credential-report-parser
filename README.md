# credential-report-parser

Helps identify misconfigured or stale AWS IAM user accounts

## Pre-requisites

- Python3

- Pip3

- Virtualenv

## Installation

1. Install required Python packages

    ```bash
    cd <path-to-credential-report-parser>
    python3 -m pip install -r requirements.txt
    ```

2. Create and activate virtual environment

    ```bash
    virtualenv env
    source ./env/bin/activate
    ```

## Usage Examples

1. See help menu:

    ```bash
    python3 ./credential-report-parser.py --help
    ```

2. List users' last logged in time:

    ```bash
    python3 ./credential-report-parser.py last_used
    ```

3. List only users that did not log in within the last 30 days:

    ```bash
    python3 ./credential-report-parser.py --days 30 last_used
    ```

4. List users' last password change time:

    ```bash
    python3 ./credential-report-parser.py password_change_dates
    ```

5. List only users that did not reset their password within the last 60 days:

    ```bash
    python3 ./credential-report-parser.py --days 60 password_change_dates
    ```

6. Show multi-factor authentication (MFA) status of users (`true` means MFA is enabled and `false` means it is not enabled for that user):

    ```bash
    python3 ./credential-report-parser.py mfa_enabled
    ```
    
