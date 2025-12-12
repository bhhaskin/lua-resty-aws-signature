# lua-resty-aws-signature

## Overview
**lua-resty-aws-signature** is an AWS Signature Version 4 signing library for OpenResty, allowing secure authentication with AWS services.

## Features
- Implements AWS Signature Version 4
- Supports signing requests for AWS services such as **S3, API Gateway (execute-api), IAM, and others**
- **Session token support** for temporary AWS credentials (STS)
- **Case-insensitive header handling** for HTTP compliance
- **Automatic signing of all x-amz-* headers**
- **Proper query string encoding and sorting** per AWS requirements
- **Comprehensive error handling** with detailed error messages
- Uses **lua-resty-openssl** for cryptographic operations
- Compatible with **OpenResty** and **Nginx Lua Module**
- Optimized for performance and security

## Installation
You can install **lua-resty-aws-signature** using [LuaRocks](https://luarocks.org/):

```sh
luarocks install lua-resty-aws-signature
```

## Usage
### Importing the Library
```lua
local aws_signature = require("resty.aws_signature")
```

### Signing an AWS Request
```lua
local opts = {
    method = "GET",
    uri = "/test.txt",
    service = "s3",
    region = "us-east-1",
    headers = {
        ["Host"] = "my-bucket.s3.amazonaws.com"
    },
    access_key = "ASIAUZABC123456",
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    date_iso8601 = "20250225T155154Z",
    date_stamp = "20250225"
}

local signed_request, err = aws_signature.sign_request(opts)
if not signed_request then
    ngx.log(ngx.ERR, "Failed to sign request: ", err)
    return ngx.exit(500)
end

print(signed_request.headers["Authorization"])
```

### Using Temporary Credentials (Session Tokens)
```lua
local opts = {
    method = "GET",
    uri = "/test.txt",
    service = "s3",
    region = "us-east-1",
    headers = {
        ["Host"] = "my-bucket.s3.amazonaws.com"
    },
    access_key = "ASIAUZABC123456",
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    session_token = "FwoGZXIvYXdzEBMa...",  -- Session token from STS
    date_iso8601 = "20250225T155154Z",
    date_stamp = "20250225"
}

local signed_request, err = aws_signature.sign_request(opts)
if not signed_request then
    ngx.log(ngx.ERR, "Failed to sign request: ", err)
    return ngx.exit(500)
end
```

### Using with OpenResty
You can integrate **lua-resty-aws-signature** within OpenResty for proxying AWS requests. Example for signing an S3 request:

```lua
local aws_signature = require("resty.aws_signature")
local http = require("resty.http")

local opts = {
    method = "GET",
    uri = "/test.txt",
    service = "s3",
    region = "us-east-1",
    headers = {
        ["Host"] = "my-bucket.s3.amazonaws.com"
    },
    access_key = "ASIAUZABC123456",
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    date_iso8601 = "20250225T155154Z",
    date_stamp = "20250225"
}

local signed_request, err = aws_signature.sign_request(opts)
if not signed_request then
    ngx.log(ngx.ERR, "Failed to sign request: ", err)
    return ngx.exit(500)
end

local httpc = http.new()
local res, err = httpc:request_uri("https://my-bucket.s3.amazonaws.com/test.txt", {
    method = "GET",
    headers = signed_request.headers
})

if not res then
    ngx.log(ngx.ERR, "Request failed: ", err)
    return ngx.exit(500)
end

ngx.status = res.status
ngx.say(res.body)
ngx.exit(res.status)
```

### Using Custom Header Signing
```lua
local opts = {
    method = "PUT",
    uri = "/document.pdf",
    service = "s3",
    region = "us-east-1",
    headers = {
        ["Host"] = "my-bucket.s3.amazonaws.com",
        ["Content-Type"] = "application/pdf"
    },
    signed_headers = {"content-type"},  -- Include Content-Type in signature
    access_key = "ASIAUZABC123456",
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    date_iso8601 = "20250225T155154Z",
    date_stamp = "20250225"
}

local signed_request, err = aws_signature.sign_request(opts)
```

### Generating Presigned URLs
```lua
local aws_signature = require("resty.aws_signature")

-- Generate a presigned URL valid for 1 hour
local opts = {
    method = "GET",
    uri = "/private/document.pdf",
    host = "my-bucket.s3.us-east-1.amazonaws.com",
    service = "s3",
    region = "us-east-1",
    access_key = "ASIAUZABC123456",
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    date_iso8601 = "20250225T155154Z",
    date_stamp = "20250225",
    expires = 3600  -- URL valid for 1 hour
}

local presigned_url, err = aws_signature.presign_url(opts)
if not presigned_url then
    ngx.log(ngx.ERR, "Failed to generate presigned URL: ", err)
    return ngx.exit(500)
end

-- URL can now be shared or used directly in browsers
ngx.say(presigned_url)
```

### Using Date Helper
```lua
local aws_signature = require("resty.aws_signature")

-- Generate current date/time in AWS format
local dates = aws_signature.generate_dates()

local opts = {
    method = "GET",
    uri = "/test.txt",
    service = "s3",
    region = "us-east-1",
    headers = {
        ["Host"] = "my-bucket.s3.amazonaws.com"
    },
    access_key = "ASIAUZABC123456",
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    date_iso8601 = dates.iso8601,  -- Auto-generated
    date_stamp = dates.stamp        -- Auto-generated
}

local signed_request, err = aws_signature.sign_request(opts)
```

### S3 POST Policy Signing (Browser Uploads)
```lua
local aws_signature = require("resty.aws_signature")
local cjson = require("cjson")

-- Create S3 POST policy
local policy = {
    expiration = "2025-12-31T12:00:00.000Z",
    conditions = {
        {bucket = "my-bucket"},
        {"starts-with", "$key", "uploads/"},
        {"acl", "private"},
        {"success_action_status", "201"}
    }
}

local policy_json = cjson.encode(policy)
local dates = aws_signature.generate_dates()

local result, err = aws_signature.sign_post_policy({
    policy = policy_json,
    secret_key = "5wfFi0FEaaaaacccc1111111111111",
    date_stamp = dates.stamp,
    region = "us-east-1"
})

if not result then
    ngx.log(ngx.ERR, "Failed to sign policy: ", err)
    return ngx.exit(500)
end

-- Use result.policy and result.signature in HTML form
ngx.say("Policy: ", result.policy)
ngx.say("Signature: ", result.signature)
```

## API Reference

### `sign_request(opts)`

Signs an AWS request using Signature Version 4.

**Parameters:**
- `opts` (table) - Configuration options:
  - `method` (string, optional) - HTTP method (default: "GET")
  - `uri` (string, optional) - Request URI path (default: "/")
  - `query_string` (string, optional) - Query string parameters (will be encoded and sorted)
  - `headers` (table, required) - HTTP headers including `Host` (case-insensitive)
  - `payload` (string, optional) - Request body (default: "")
  - `service` (string, required) - AWS service name (e.g., "s3", "execute-api")
  - `region` (string, required) - AWS region (e.g., "us-east-1")
  - `access_key` (string, required) - AWS access key ID
  - `secret_key` (string, required) - AWS secret access key
  - `session_token` (string, optional) - AWS session token for temporary credentials
  - `signed_headers` (table, optional) - Additional headers to include in signature (e.g., `{"content-type", "content-md5"}`)
  - `date_iso8601` (string, required) - ISO8601 formatted date-time (e.g., "20250225T155154Z")
  - `date_stamp` (string, required) - Date stamp (e.g., "20250225")

**Returns:**
- On success: `{ headers = {...} }` - Table with signed headers including `Authorization`
- On failure: `nil, error_message` - Nil and an error description string

**Notes:**
- Headers are case-insensitive (both `Host` and `host` work)
- All `x-amz-*` headers are automatically included in the signature
- Input headers table is not mutated (a copy is returned)
- Query strings are automatically encoded and sorted per AWS requirements

### `presign_url(opts)`

Generates a presigned URL for AWS requests (query string authentication).

**Parameters:**
- `opts` (table) - Configuration options:
  - `method` (string, optional) - HTTP method (default: "GET")
  - `uri` (string, optional) - Request URI path (default: "/")
  - `host` (string, required) - Host name (e.g., "my-bucket.s3.us-east-1.amazonaws.com")
  - `scheme` (string, optional) - URL scheme (default: "https")
  - `query_params` (table, optional) - Additional query parameters
  - `service` (string, required) - AWS service name (e.g., "s3")
  - `region` (string, required) - AWS region (e.g., "us-east-1")
  - `access_key` (string, required) - AWS access key ID
  - `secret_key` (string, required) - AWS secret access key
  - `session_token` (string, optional) - AWS session token for temporary credentials
  - `date_iso8601` (string, required) - ISO8601 formatted date-time
  - `date_stamp` (string, required) - Date stamp
  - `expires` (number, optional) - URL validity in seconds (default: 3600, max: 604800)

**Returns:**
- On success: `url_string` - Presigned URL that can be used directly
- On failure: `nil, error_message` - Nil and an error description string

### `generate_dates(timestamp)`

Helper function to generate date/time in AWS format.

**Parameters:**
- `timestamp` (number, optional) - Unix timestamp (default: current time)

**Returns:**
- `{ iso8601 = "...", stamp = "..." }` - Table with ISO8601 and date stamp

### `sign_post_policy(opts)`

Signs an S3 POST policy for browser-based uploads.

**Parameters:**
- `opts` (table) - Configuration options:
  - `policy` (string, required) - JSON policy document
  - `secret_key` (string, required) - AWS secret access key
  - `date_stamp` (string, required) - Date stamp
  - `region` (string, required) - AWS region
  - `service` (string, optional) - AWS service name (default: "s3")

**Returns:**
- On success: `{ policy = "base64_encoded_policy", signature = "hex_signature" }`
- On failure: `nil, error_message`

## Testing
The module includes **Busted** tests for verification:
```sh
make test
```

## License
This project is licensed under the **MIT License**.
