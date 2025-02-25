# Generating Test Signatures with AWS Python Example

## Overview
To validate the correctness of `lua-resty-aws-signature`, you can generate test signatures using the official AWS Python example script. This ensures that the generated signatures match AWS expectations.

## Prerequisites
Ensure you have the following installed:
- Python 3.x
- `requests` library (if making real AWS requests)
- AWS credentials with appropriate permissions

## Example Script
The following Python script generates an AWS Signature V4 authorization header:

```python
import datetime
import hashlib
import hmac
import os

# AWS access keys
access_key = 'ASIAUZABC123456'
secret_key = '5wfFi0FEaaaaacccc1111111111111/'

# Request parameters
method = 'GET'
service = 's3'
region = 'us-east-1'
bucket_name = 'my-bucket'
object_key = 'test.txt'

# Create request details
host = f"{bucket_name}.s3.amazonaws.com"
endpoint = f"/{object_key}"

# Create a datetime object for signing
t = datetime.datetime.utcnow()
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d')

# Compute payload hash (SHA-256 of an empty string)
payload_hash = hashlib.sha256(b'').hexdigest()

# Create the canonical request
canonical_uri = endpoint
canonical_querystring = ''
canonical_headers = (f"host:{host}\n"
                     f"x-amz-content-sha256:{payload_hash}\n"
                     f"x-amz-date:{amzdate}\n")
signed_headers = "host;x-amz-content-sha256;x-amz-date"

canonical_request = (method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n'
                     + canonical_headers + '\n' + signed_headers + '\n' + payload_hash)

# Create the string to sign
algorithm = 'AWS4-HMAC-SHA256'
credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
string_to_sign = (algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' +
                  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
    return kSigning

# Generate the signature
signing_key = getSignatureKey(secret_key, datestamp, region, service)
signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

# Construct authorization header
authorization_header = (f"{algorithm} Credential={access_key}/{credential_scope}, "
                        f"SignedHeaders={signed_headers}, Signature={signature}")

# Debug Output with Spacers
def print_section(title, content):
    print("\n" + "=" * 50)
    print(f"{title}")
    print("=" * 50)
    print(content)

# Print debug information with section headers
print_section("REQUEST DETAILS", f"Request URL: https://{host}{canonical_uri}\nMethod: {method}")

print_section("CANONICAL REQUEST", canonical_request)

print_section("STRING TO SIGN", string_to_sign)

print_section("GENERATED SIGNATURE", signature)

print_section("AUTHORIZATION HEADER", authorization_header)

print_section("HEADERS", f"""
Host: {host}
x-amz-date: {amzdate}
x-amz-content-sha256: {payload_hash}
Authorization: {authorization_header}
""")
```

## Using the Generated Signature
1. Run the script.
2. Copy the outputted signature and authorization header.
3. Compare with the `lua-resty-aws-signature` output to validate correctness.

## Troubleshooting
- Ensure the AWS credentials match those used in Lua.
- Verify the timestamp and request parameters align exactly with Lua requests.
- Check the computed payload hash and canonical request formatting.

By following this guide, you can confidently verify AWS Signature V4 correctness in your OpenResty environment.

