local _M = {
    _VERSION = '0.3-0'
  }
  
  local hmac = require "resty.openssl.hmac"
  local sha256 = require "resty.openssl.digest"
  
  -- Pure Lua function to convert binary string to hexadecimal
  local function to_hex(str)
      return (str:gsub(".", function(c)
          return string.format("%02x", string.byte(c))
      end))
  end
  
  -- Function to compute HMAC-SHA256
  local function hmac_sha256(key, data)
      local hmac_obj, err = hmac.new(key, "sha256")
      if not hmac_obj then
          return nil, "Failed to create HMAC: " .. err
      end
      hmac_obj:update(data)
      return hmac_obj:final()
  end
  
  -- Function to compute SHA-256 hash
  local function hash_sha256(data)
      local digest, err = sha256.new("sha256")
      if not digest then
          return nil, "Failed to create digest: " .. err
      end
      digest:update(data)
      return to_hex(digest:final())
  end
  
  -- Function to derive AWS Signature v4 signing key
  local function get_signature_key(secret_key, date_stamp, region, service)
      local k_date = hmac_sha256("AWS4" .. secret_key, date_stamp)
      local k_region = hmac_sha256(k_date, region)
      local k_service = hmac_sha256(k_region, service)
      return hmac_sha256(k_service, "aws4_request")
  end
  
  local function aws_uri_encode(path)
    -- Characters that may appear unescaped in the canonical URI
    local safe = "[A-Za-z0-9._~-]"

    local function encode_byte(c)
        return string.format("%%%02X", string.byte(c))
    end

    -- Encode every segment but preserve the '/' separators
    local encoded = path:gsub("([^/]+)", function(segment)
        -- 1st pass: encode everything except the safe set
        segment = segment:gsub("([^" .. safe .. "])", encode_byte)
        -- 2nd pass: encode every '%' that was introduced above
        return segment:gsub("%%", "%%25")
    end)

    return encoded
  end

  -- Function to generate AWS Signature v4 headers
  function _M.sign_request(opts)
      local method = opts.method or "GET"
      local uri = aws_uri_encode(opts.uri or "/")
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
  
      -- Ensure `x-amz-content-sha256` is set for S3 requests
      if service == "s3" then
          headers["x-amz-content-sha256"] = headers["x-amz-content-sha256"] or hash_sha256(payload)
      end
  
      -- Ensure `x-amz-date` is included in headers
      headers["x-amz-date"] = date_iso8601
  
      local canonical_headers = "host:" .. headers["Host"] .. "\n"
      local signed_headers = "host"
  
      if service == "s3" then
          canonical_headers = canonical_headers .. "x-amz-content-sha256:" .. headers["x-amz-content-sha256"] .. "\n"
          signed_headers = signed_headers .. ";x-amz-content-sha256"
      end
  
      canonical_headers = canonical_headers .. "x-amz-date:" .. headers["x-amz-date"] .. "\n"
      signed_headers = signed_headers .. ";x-amz-date"
  
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
  
      headers["Authorization"] = authorization_header
      headers["x-amz-content-sha256"] = headers["x-amz-content-sha256"]
      headers["x-amz-date"] = date_iso8601
  
      return { headers = headers }
  end
  
  return _M