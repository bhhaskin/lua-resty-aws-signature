local _M = {
  _VERSION = '0.2-0'
}

local hmac = require "resty.openssl.hmac"
local sha256 = require "resty.openssl.digest"

local function to_hex(str)
    return (str:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hmac_sha256(key, data)
    local hmac_obj, err = hmac.new(key, "sha256")
    if not hmac_obj then
        return nil, "Failed to create HMAC: " .. err
    end
    hmac_obj:update(data)
    return hmac_obj:final()
end

local function hash_sha256(data)
    local digest, err = sha256.new("sha256")
    if not digest then
        return nil, "Failed to create digest: " .. err
    end
    digest:update(data)
    return to_hex(digest:final())
end

local function get_signature_key(secret_key, date_stamp, region, service)
    local k_date = hmac_sha256("AWS4" .. secret_key, date_stamp)
    local k_region = hmac_sha256(k_date, region)
    local k_service = hmac_sha256(k_region, service)
    return hmac_sha256(k_service, "aws4_request")
end

function _M.sign_request(opts)
    local method = opts.method or "GET"
    local uri = opts.uri or "/"
    local query_string = opts.query_string or ""
    local headers = opts.headers or {}
    local payload = opts.payload or ""
    
    local service = opts.service
    local region = opts.region
    local access_key = opts.access_key
    local secret_key = opts.secret_key
    local date_iso8601 = opts.date_iso8601
    local date_stamp = opts.date_stamp

    if not headers["Host"] then
        error("Missing required 'Host' header")
    end

    if service == "s3" and not headers["x-amz-content-sha256"] then
        headers["x-amz-content-sha256"] = hash_sha256(payload)
    end

    local canonical_headers = "host:" .. headers["Host"]:lower() .. "\n"
    local signed_headers = "host"

    if service == "s3" then
        canonical_headers = canonical_headers .. "x-amz-content-sha256:" .. headers["x-amz-content-sha256"] .. "\n"
        signed_headers = signed_headers .. ";x-amz-content-sha256"
    end

    local canonical_query_string = query_string or ""

    local payload_hash = hash_sha256(payload)
    local canonical_request = table.concat({
        method,
        uri,
        canonical_query_string,
        canonical_headers,
        signed_headers,
        payload_hash
    }, "\n")


    local canonical_request_hash = hash_sha256(canonical_request)
    local credential_scope = table.concat({ date_stamp, region, service, "aws4_request" }, "/")
    local string_to_sign = table.concat({
        "AWS4-HMAC-SHA256",
        date_iso8601,
        credential_scope,
        canonical_request_hash
    }, "\n")

    local signing_key = get_signature_key(secret_key, date_stamp, region, service)
    local signature = to_hex(hmac_sha256(signing_key, string_to_sign))
    local authorization_header = string.format(
        "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
        access_key, credential_scope, signed_headers, signature
    )

    return {
        headers = {
            ["Authorization"] = authorization_header,
            ["x-amz-date"] = date_iso8601,
            ["Host"] = headers["Host"]
        }
    }
end

return _M
