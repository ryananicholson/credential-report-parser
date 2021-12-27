#!/usr/bin/python3

import requests
import argparse
import os
import json
import hashlib
import datetime
import hmac
import base64

### Below is from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html#sig-v4-examples-post THANKS AWS!

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def sendrequest(request_parameters):

    method = 'POST'
    service = 'iam'
    host = 'iam.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://iam.amazonaws.com/'
    content_type = 'application/x-www-form-urlencoded; charset=utf-8'
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query 
    # string (use '/' if no path)
    canonical_uri = '/'

    ## Step 3: Create the canonical query string. In this example, request
    # parameters are passed in the body of the request and the query string
    # is blank.
    canonical_querystring = ''

    # Step 4: Create the canonical headers. Header names must be trimmed
    # and lowercase, and sorted in code point order from low to high.
    # Note that there is a trailing \n.
    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers include those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    # For DynamoDB, content-type and x-amz-target are also required.
    signed_headers = 'content-type;host;x-amz-date'

    # Step 6: Create payload hash. In this example, the payload (body of
    # the request) contains the request parameters.
    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

    # Step 7: Combine elements to create canonical request
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash


    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = getSignatureKey(SecretKey, date_stamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # Put the signature information in a header named Authorization.
    authorization_header = algorithm + ' ' + 'Credential=' + AccessKey + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
    headers = {'Content-Type':content_type,
            'X-Amz-Date':amz_date,
            'Authorization':authorization_header}
    try:
        r = requests.post(endpoint, data=request_parameters, headers=headers)
        return r.text
    except:
        print("\033[31mERROR:\033[0m Issue sending request to AWS!")

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
            resultJson = json.loads(requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + roleName).text)
            AccessKey = resultJson['AccessKeyId']
        except:
            print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
            exit(1)
        try:
            SecretKey = resultJson['SecretAccessKey']
        except:
            print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
            exit(1)
        try:
            SessionToken = resultJson['Token']
        except:
            print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
            exit(1)
if AccessKey == None or SecretKey == None:
    print("\033[31mERROR:\033[0m Cannot retrieve AWS credentials. Use environment variables, .aws/credentials file, or IMDS to give this app access to AWS.")
    exit(1)

sendrequest("Action=GenerateCredentialReport&Version=2010-05-08")
report = sendrequest("Action=GetCredentialReport&Version=2010-05-08")
for line in report.split("\n"):
    if line.startswith("    <Content>"):
        b64Content = line.split(">")[1].split("<")[0]
        reportDecoded = base64.b64decode(b64Content).decode('utf-8')
if args.action == "mfa_enabled":
    print("user,mfa_enabled")
    for line in reportDecoded.split("\n"):
        if not line.startswith("user,arn,user_creation"):
            print(line.split(",")[0] + "," + line.split(",")[7])
if args.action == "password_change_dates":
    if args.days != None:
        hits = False
        for line in reportDecoded.split("\n"):
            if not line.startswith("user,arn,user_creation") and not line.startswith("<") and not line.split(",")[3] == "false":
                nowDate = datetime.date.today()
                logDate = line.split(",")[5]
                changeDate = datetime.date(int(logDate.split("-")[0]), int(logDate.split("-")[1]), int(logDate.split("-")[2].split("T")[0]))
                delta = nowDate - changeDate
                if delta.days > args.days:
                    if not hits:
                        print("non_compliant_user,days_since_password_change")
                    print(line.split(",")[0] + "," + str(delta.days))
                    hits == True
    else:
        print("user,password_last_changed")
        for line in reportDecoded.split("\n"):
            if not line.startswith("user,arn,user_creation") and not line.startswith("<") and not line.split(",")[3] == "false":
                if not line.startswith("user,arn,user_creation"):
                    print(line.split(",")[0] + "," + line.split(",")[5])
if args.action == "last_used":
    if args.days != None:
        hits = False
        for line in reportDecoded.split("\n"):
            if not line.startswith("user,arn,user_creation") and not line.startswith("<"):
                nowDate = datetime.date.today()
                if line.split(",")[4] == "N/A":
                    logDate = line.split(",")[2]
                else:
                    logDate = line.split(",")[4]
                changeDate = datetime.date(int(logDate.split("-")[0]), int(logDate.split("-")[1]), int(logDate.split("-")[2].split("T")[0]))
                delta = nowDate - changeDate
                if delta.days > args.days:
                    if not hits:
                        print("non_compliant_user,days_since_last_login")
                    print(line.split(",")[0] + "," + str(delta.days))
                    hits = True
    else:
        print("user,password_last_used")
        for line in reportDecoded.split("\n"):
            if not line.startswith("user,arn,user_creation") and not line.startswith("<"):
                if not line.startswith("user,arn,user_creation"):
                    print(line.split(",")[0] + "," + line.split(",")[4])