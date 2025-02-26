# lua-resty-aws-signature

## Overview
**lua-resty-aws-signature** is an AWS Signature Version 4 signing library for OpenResty, allowing secure authentication with AWS services.

## Features
- Implements AWS Signature Version 4
- Supports signing requests for AWS services such as **S3, API Gateway (execute-api), IAM, and others**
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

local signed_request = aws_signature.sign_request(opts)
print(signed_request.headers["Authorization"])
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

local signed_request = aws_signature.sign_request(opts)

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

## Testing
The module includes **Busted** tests for verification:
```sh
make test
```

## License
This project is licensed under the **MIT License**.
