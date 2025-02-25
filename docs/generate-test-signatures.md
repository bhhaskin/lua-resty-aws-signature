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

# AWS access keys
access_key = 'ASIAUZABC123456'  
secret_key = '5wfFi0FEaaaaacccc1111111111111'

# Request parameters
method = 'GET'
service = 'execute-api'
host = 'myapi123.execute-api.us-east-1.amazonaws.com'
region = 'us-east-1'
endpoint = '/Prod/hello'

# Create a datetime object for signing (fixed time for testing consistency)
t = datetime.datetime(2025, 2, 25, 15, 51, 54, tzinfo=datetime.timezone.utc)
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d')

# **Step 1: Create the Canonical Request**
# S3 requires x-amz-content-sha256 (even for GET)
payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

# Canonical headers (Only required headers: 'host' for general, 'x-amz-content-sha256' for S3)
canonical_headers = f'host:{host}\n'
signed_headers = 'host'

# **Include x-amz-content-sha256 for S3**
if service == 's3':
    canonical_headers += f'x-amz-content-sha256:{payload_hash}\n'
    signed_headers += ';x-amz-content-sha256'

# Canonical Request
canonical_uri = endpoint
canonical_querystring = ''
canonical_request = (method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n'
                     + canonical_headers + '\n' + signed_headers + '\n' + payload_hash)

# Debug Output: Canonical Request
print("\n========== Canonical Request (Python) ==========")
print(canonical_request)
print("=======================================")

# Compute Canonical Request Hash
canonical_request_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
print("\nCanonical Request Hash:", canonical_request_hash)

# **Step 2: Create the String to Sign**
algorithm = 'AWS4-HMAC-SHA256'
credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
string_to_sign = (algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + canonical_request_hash)

# Debug Output: String to Sign
print("\n========== String to Sign ==========")
print(string_to_sign)
print("===================================")

# **Step 3: Compute the Signing Key**
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

# Derive the signing key
kDate = sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
kRegion = sign(kDate, region)
kService = sign(kRegion, service)
kSigning = sign(kService, "aws4_request")

# Debug Output: Signing Key Derivation
print("\n========== Signing Key (Hex) ==========")
print("K_DATE:", kDate.hex())
print("K_REGION:", kRegion.hex())
print("K_SERVICE:", kService.hex())
print("K_SIGNING:", kSigning.hex())
print("===================================")

# **Step 4: Compute the Signature**
signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

# Debug Output: Computed Signature
print("\n========== Computed Signature ==========")
print(signature)
print("===================================")

# **Step 5: Construct Authorization Header**
authorization_header = (algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +
                        'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature)

# Debug Output: Authorization Header
print("\n========== Authorization Header ==========")
print(authorization_header)
print("===================================")
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

