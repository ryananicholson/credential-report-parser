#!/usr/bin/python3

import requests
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("action", help="The action to perform against the credential report (password_change_dates, mfa_enabled, last_used)")
parser.add_argument("-d", "--days", help="Only show accounts with password_change_dates or last_used greater than this number of days", type=int)
parser.add_argument("-p", "--profile", help="Name of profile if using .aws/credentials file. Defaults to 'default'", default="default")
args = parser.parse_args()

# Command syntax error handling

if args.action != "password_change_dates" and args.action != "mfa_enabled" and args.action != "last_used":
    print("\033[31mERROR:\033[0m Invalid action! Must use \033[33mpassword_change_dates\033[0m, \033[33mmfa_enabled\033[0m, or \033[33mlast_used\033[0m")
    exit(1)
if args.action == "mfa_enabled" and args.days != None:
    print("\033[31mERROR:\033[0m mfa_enabled does not accept -d/--days argument!")
    exit(1)

# Check for AWS credentials

## Environment variables

try:
    AccessKey = os.environ['AWS_ACCESS_KEY_ID']
    SecretKey = os.environ['AWS_SECRET_ACCESS_KEY']
    try:
        SessionToken = os.environ['AWS_SESSION_TOKEN']
    except:
        SessionToken = ""
except: 
    if os.path.exists(os.path.expanduser('~') + "/.aws/credentials"):
        f = open(os.path.expanduser('~') + "/.aws/credentials", "r")
        found = False
        for line in f.readlines():
            if line.startswith("["):
                found = False
            elif found and not line.startswith("["):
                if line.startswith("aws_access_key_id"):
                    AccessKey = line.split("=")[1].split(" ")[1].strip()
                if line.startswith("aws_secret_access_key"):
                    SecretKey = line.split("=")[1].split(" ")[1].strip()
            else:
                found == False
            if line == "[" + args.profile + "]\n":
                found = True
    else:
        try:
            roleName = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials").text
            AccessKey = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + roleName)
        except:
            print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
            exit(1)
        try:
            roleName = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials").text
            SecretKey = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + roleName)
        except:
            print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
            exit(1)
        try:
            roleName = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials").text
            SessionToken = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + roleName)
        except:
            print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
            exit(1)
print(AccessKey)