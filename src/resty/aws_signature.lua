local _M = {
    _VERSION = '1.0-0'
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
      local k_date, err = hmac_sha256("AWS4" .. secret_key, date_stamp)
      if not k_date then return nil, err end

      local k_region, err = hmac_sha256(k_date, region)
      if not k_region then return nil, err end

      local k_service, err = hmac_sha256(k_region, service)
      if not k_service then return nil, err end

      return hmac_sha256(k_service, "aws4_request")
  end
  
  local function aws_uri_encode(path)
    local safe = "[A-Za-z0-9._~-]"

    local function enc(c)          -- %HH in upper‑case hex
        return string.format("%%%02X", string.byte(c))
    end

    -- Encode each path segment but keep "/" separators intact
    return path:gsub("([^/]+)", function(segment)
        return segment:gsub("([^" .. safe .. "])", enc)
    end)
  end

  -- Normalize headers to lowercase keys
  local function normalize_headers(headers)
      local normalized = {}
      for k, v in pairs(headers) do
          normalized[k:lower()] = v
      end
      return normalized
  end

  -- Copy table
  local function copy_table(t)
      local copy = {}
      for k, v in pairs(t) do
          copy[k] = v
      end
      return copy
  end

  -- Encode query string parameter
  local function encode_query_param(str)
      local safe = "[A-Za-z0-9._~-]"
      return str:gsub("([^" .. safe .. "])", function(c)
          return string.format("%%%02X", string.byte(c))
      end)
  end

  -- Parse and sort query string for canonical request
  local function canonicalize_query_string(query_string)
      if not query_string or query_string == "" then
          return ""
      end

      local params = {}
      for pair in query_string:gmatch("([^&]+)") do
          local key, value = pair:match("([^=]+)=?(.*)")
          if key then
              key = encode_query_param(key)
              value = encode_query_param(value)
              table.insert(params, {key = key, value = value})
          end
      end

      -- Sort by key, then by value
      table.sort(params, function(a, b)
          if a.key == b.key then
              return a.value < b.value
          end
          return a.key < b.key
      end)

      local canonical_parts = {}
      for _, param in ipairs(params) do
          if param.value ~= "" then
              table.insert(canonical_parts, param.key .. "=" .. param.value)
          else
              table.insert(canonical_parts, param.key .. "=")
          end
      end

      return table.concat(canonical_parts, "&")
  end

  -- Function to generate AWS Signature v4 headers
  function _M.sign_request(opts)
      -- Validate required parameters
      if not opts.service then
          return nil, "Missing required parameter: service"
      end
      if not opts.region then
          return nil, "Missing required parameter: region"
      end
      if not opts.access_key then
          return nil, "Missing required parameter: access_key"
      end
      if not opts.secret_key then
          return nil, "Missing required parameter: secret_key"
      end
      if not opts.date_iso8601 then
          return nil, "Missing required parameter: date_iso8601"
      end
      if not opts.date_stamp then
          return nil, "Missing required parameter: date_stamp"
      end

      local method = opts.method or "GET"
      local uri = aws_uri_encode(opts.uri or "/")
      local query_string = opts.query_string or ""
      local payload = opts.payload or ""

      local service = opts.service
      local region = opts.region
      local access_key = opts.access_key
      local secret_key = opts.secret_key
      local date_iso8601 = opts.date_iso8601
      local date_stamp = opts.date_stamp
      local session_token = opts.session_token

      -- Copy and normalize headers to avoid mutation and handle case-insensitivity
      local input_headers = opts.headers or {}
      local normalized = normalize_headers(input_headers)
      local headers = copy_table(input_headers)

      if not normalized["host"] then
          return nil, "Missing required 'Host' header"
      end

      -- Add x-amz-date header
      headers["x-amz-date"] = date_iso8601

      -- Add session token if present (for temporary credentials)
      if session_token then
          headers["x-amz-security-token"] = session_token
      end

      -- Calculate payload hash
      local payload_hash, err = hash_sha256(payload)
      if not payload_hash then
          return nil, "Failed to hash payload: " .. err
      end

      -- For S3, add x-amz-content-sha256 header
      if service == "s3" then
          if not headers["x-amz-content-sha256"] then
              headers["x-amz-content-sha256"] = payload_hash
          end
      end

      -- Normalize headers again with all added headers
      normalized = normalize_headers(headers)

      -- Build canonical headers and signed headers list
      -- Collect all headers that should be signed
      local custom_signed_headers = opts.signed_headers or {}
      local headers_to_sign = {}

      for name, value in pairs(normalized) do
          local should_sign = false

          -- Always sign host and x-amz-* headers
          if name == "host" or name:sub(1, 6) == "x-amz-" then
              should_sign = true
          end

          -- Check if in custom signed headers list
          for _, custom_header in ipairs(custom_signed_headers) do
              if name == custom_header:lower() then
                  should_sign = true
                  break
              end
          end

          if should_sign then
              table.insert(headers_to_sign, {name = name, value = value})
          end
      end

      -- Sort headers by name
      table.sort(headers_to_sign, function(a, b)
          return a.name < b.name
      end)

      -- Build canonical headers string and signed headers list
      local canonical_headers_parts = {}
      local signed_headers_parts = {}
      for _, header in ipairs(headers_to_sign) do
          table.insert(canonical_headers_parts, header.name .. ":" .. header.value)
          table.insert(signed_headers_parts, header.name)
      end

      local canonical_headers = table.concat(canonical_headers_parts, "\n") .. "\n"
      local signed_headers = table.concat(signed_headers_parts, ";")

      -- Canonicalize query string
      local canonical_query_string = canonicalize_query_string(query_string)

      -- Build canonical request
      local canonical_request = table.concat({
          method,
          uri,
          canonical_query_string,
          canonical_headers,
          signed_headers,
          payload_hash
      }, "\n")

      local canonical_request_hash, err = hash_sha256(canonical_request)
      if not canonical_request_hash then
          return nil, "Failed to hash canonical request: " .. err
      end

      -- Build string to sign
      local credential_scope = table.concat({ date_stamp, region, service, "aws4_request" }, "/")
      local string_to_sign = table.concat({
          "AWS4-HMAC-SHA256",
          date_iso8601,
          credential_scope,
          canonical_request_hash
      }, "\n")

      -- Calculate signature
      local signing_key, err = get_signature_key(secret_key, date_stamp, region, service)
      if not signing_key then
          return nil, "Failed to derive signing key: " .. err
      end

      local signature_bytes, err = hmac_sha256(signing_key, string_to_sign)
      if not signature_bytes then
          return nil, "Failed to calculate signature: " .. err
      end

      local signature = to_hex(signature_bytes)

      -- Build authorization header
      local authorization_header = string.format(
          "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
          access_key, credential_scope, signed_headers, signature
      )

      headers["Authorization"] = authorization_header

      return { headers = headers }
  end

  -- Function to generate presigned URLs for AWS requests
  function _M.presign_url(opts)
      -- Validate required parameters
      if not opts.service then
          return nil, "Missing required parameter: service"
      end
      if not opts.region then
          return nil, "Missing required parameter: region"
      end
      if not opts.access_key then
          return nil, "Missing required parameter: access_key"
      end
      if not opts.secret_key then
          return nil, "Missing required parameter: secret_key"
      end
      if not opts.date_iso8601 then
          return nil, "Missing required parameter: date_iso8601"
      end
      if not opts.date_stamp then
          return nil, "Missing required parameter: date_stamp"
      end
      if not opts.host then
          return nil, "Missing required parameter: host"
      end

      local method = opts.method or "GET"
      local uri = aws_uri_encode(opts.uri or "/")
      local expires = opts.expires or 3600  -- Default 1 hour
      local query_params = opts.query_params or {}
      local session_token = opts.session_token

      local service = opts.service
      local region = opts.region
      local access_key = opts.access_key
      local secret_key = opts.secret_key
      local date_iso8601 = opts.date_iso8601
      local date_stamp = opts.date_stamp
      local host = opts.host
      local scheme = opts.scheme or "https"

      -- Validate expires (max 7 days for S3)
      if expires > 604800 then
          return nil, "Expires cannot exceed 604800 seconds (7 days)"
      end

      -- Build credential scope
      local credential_scope = table.concat({ date_stamp, region, service, "aws4_request" }, "/")

      -- Build X-Amz-* query parameters
      local amz_params = {
          ["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256",
          ["X-Amz-Credential"] = access_key .. "/" .. credential_scope,
          ["X-Amz-Date"] = date_iso8601,
          ["X-Amz-Expires"] = tostring(expires),
          ["X-Amz-SignedHeaders"] = "host"
      }

      -- Add security token if present
      if session_token then
          amz_params["X-Amz-Security-Token"] = session_token
      end

      -- Merge with user-provided query parameters
      local all_params = {}
      for k, v in pairs(query_params) do
          all_params[k] = v
      end
      for k, v in pairs(amz_params) do
          all_params[k] = v
      end

      -- Build canonical query string (all params except signature, sorted)
      local param_list = {}
      for key, value in pairs(all_params) do
          table.insert(param_list, {
              key = encode_query_param(key),
              value = encode_query_param(tostring(value))
          })
      end

      -- Sort by key, then by value
      table.sort(param_list, function(a, b)
          if a.key == b.key then
              return a.value < b.value
          end
          return a.key < b.key
      end)

      local canonical_query_parts = {}
      for _, param in ipairs(param_list) do
          table.insert(canonical_query_parts, param.key .. "=" .. param.value)
      end
      local canonical_query_string = table.concat(canonical_query_parts, "&")

      -- Build canonical headers (only host for presigned URLs)
      local canonical_headers = "host:" .. host .. "\n"
      local signed_headers = "host"

      -- Calculate payload hash (UNSIGNED-PAYLOAD for presigned URLs)
      local payload_hash = "UNSIGNED-PAYLOAD"

      -- Build canonical request
      local canonical_request = table.concat({
          method,
          uri,
          canonical_query_string,
          canonical_headers,
          signed_headers,
          payload_hash
      }, "\n")

      local canonical_request_hash, err = hash_sha256(canonical_request)
      if not canonical_request_hash then
          return nil, "Failed to hash canonical request: " .. err
      end

      -- Build string to sign
      local string_to_sign = table.concat({
          "AWS4-HMAC-SHA256",
          date_iso8601,
          credential_scope,
          canonical_request_hash
      }, "\n")

      -- Calculate signature
      local signing_key, err = get_signature_key(secret_key, date_stamp, region, service)
      if not signing_key then
          return nil, "Failed to derive signing key: " .. err
      end

      local signature_bytes, err = hmac_sha256(signing_key, string_to_sign)
      if not signature_bytes then
          return nil, "Failed to calculate signature: " .. err
      end

      local signature = to_hex(signature_bytes)

      -- Build final URL with signature
      local final_url = scheme .. "://" .. host .. uri .. "?" .. canonical_query_string .. "&X-Amz-Signature=" .. signature

      return final_url
  end

  -- Helper function to generate current date/time in AWS format
  function _M.generate_dates(timestamp)
      local time = timestamp or os.time()
      local date_iso8601 = os.date("!%Y%m%dT%H%M%SZ", time)
      local date_stamp = os.date("!%Y%m%d", time)
      return {
          iso8601 = date_iso8601,
          stamp = date_stamp
      }
  end

  -- Base64 encoding function (works in both OpenResty and standard Lua)
  local function base64_encode(data)
      -- Try to use ngx.encode_base64 if available (OpenResty)
      if ngx and ngx.encode_base64 then
          return ngx.encode_base64(data)
      end

      -- Fallback to pure Lua implementation
      local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
      local result = {}

      for i = 1, #data, 3 do
          local a, b, c = data:byte(i, i + 2)
          local bitmap = a * 65536 + (b or 0) * 256 + (c or 0)

          result[#result + 1] = b64chars:sub(bitmap / 262144 % 64 + 1, bitmap / 262144 % 64 + 1)
          result[#result + 1] = b64chars:sub(bitmap / 4096 % 64 + 1, bitmap / 4096 % 64 + 1)
          result[#result + 1] = b and b64chars:sub(bitmap / 64 % 64 + 1, bitmap / 64 % 64 + 1) or '='
          result[#result + 1] = c and b64chars:sub(bitmap % 64 + 1, bitmap % 64 + 1) or '='
      end

      return table.concat(result)
  end

  -- Function to sign S3 POST policy for browser-based uploads
  function _M.sign_post_policy(opts)
      -- Validate required parameters
      if not opts.policy then
          return nil, "Missing required parameter: policy (JSON string)"
      end
      if not opts.secret_key then
          return nil, "Missing required parameter: secret_key"
      end
      if not opts.date_stamp then
          return nil, "Missing required parameter: date_stamp"
      end
      if not opts.region then
          return nil, "Missing required parameter: region"
      end

      local policy = opts.policy
      local secret_key = opts.secret_key
      local date_stamp = opts.date_stamp
      local region = opts.region
      local service = opts.service or "s3"

      -- Base64 encode the policy
      local policy_base64 = base64_encode(policy)

      -- Derive signing key
      local signing_key, err = get_signature_key(secret_key, date_stamp, region, service)
      if not signing_key then
          return nil, "Failed to derive signing key: " .. err
      end

      -- Sign the base64-encoded policy
      local signature_bytes, err = hmac_sha256(signing_key, policy_base64)
      if not signature_bytes then
          return nil, "Failed to calculate signature: " .. err
      end

      local signature = to_hex(signature_bytes)

      return {
          policy = policy_base64,
          signature = signature
      }
  end

  return _M