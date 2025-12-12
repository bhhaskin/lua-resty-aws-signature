local aws_signature = require("resty.aws_signature")

describe("lua-resty-aws-signature version check", function()
    it("should have a valid LuaRocks version number", function()
        assert.is_not_nil(aws_signature._VERSION)   -- Ensure _VERSION exists
        assert.is_string(aws_signature._VERSION)    -- Ensure it's a string
        assert.matches("^%d+%.%d+%-%d+$", aws_signature._VERSION) -- Check format X.Y-Z
    end)
end)

describe("AWS Signature v4 for S3", function()

    local opts = {
        method = "GET",
        uri = "/test.txt",
        query_string = "",
        headers = {
            Host = "my-bucket.s3.amazonaws.com",
        },
        service = "s3",
        region = "us-east-1",
        access_key = "ASIAUZABC123456",
        secret_key = "5wfFi0FEaaaaacccc1111111111111/",
        date_iso8601 = "20250225T215924Z",
        date_stamp = "20250225"
    }

    it("should generate the correct Authorization header for S3", function()
        local signed_request, err = aws_signature.sign_request(opts)
        assert.is_nil(err, "Unexpected error: " .. tostring(err))
        assert.is_not_nil(signed_request)

        local expected_signature = "e8b048d6e435351ab14e71a097a58e5796fd35822a7e3a463a071d168493d55c"

        local computed_signature = signed_request.headers["Authorization"]:match("Signature=(%w+)")

        assert.is_not_nil(computed_signature, "Signature not found in Authorization header")
        assert.are.equal(expected_signature, computed_signature)
    end)

    it("should handle case-insensitive headers", function()
        local opts_lower = {
            method = "GET",
            uri = "/test.txt",
            query_string = "",
            headers = {
                host = "my-bucket.s3.amazonaws.com",  -- lowercase 'host'
            },
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225"
        }

        local signed_request, err = aws_signature.sign_request(opts_lower)
        assert.is_nil(err, "Unexpected error: " .. tostring(err))
        assert.is_not_nil(signed_request)
        assert.is_not_nil(signed_request.headers["Authorization"])
    end)

    it("should not mutate input headers", function()
        local input_opts = {
            method = "GET",
            uri = "/test.txt",
            headers = {
                Host = "my-bucket.s3.amazonaws.com",
            },
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225"
        }

        local original_header_count = 0
        for _ in pairs(input_opts.headers) do
            original_header_count = original_header_count + 1
        end

        local signed_request, err = aws_signature.sign_request(input_opts)
        assert.is_nil(err)

        local new_header_count = 0
        for _ in pairs(input_opts.headers) do
            new_header_count = new_header_count + 1
        end

        assert.are.equal(original_header_count, new_header_count, "Input headers were mutated")
    end)

    it("should support session tokens for temporary credentials", function()
        local opts_with_token = {
            method = "GET",
            uri = "/test.txt",
            headers = {
                Host = "my-bucket.s3.amazonaws.com",
            },
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            session_token = "FwoGZXIvYXdzEBMaDEXAMPLETOKEN",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225"
        }

        local signed_request, err = aws_signature.sign_request(opts_with_token)
        assert.is_nil(err)
        assert.is_not_nil(signed_request)
        assert.is_not_nil(signed_request.headers["x-amz-security-token"])
        assert.are.equal("FwoGZXIvYXdzEBMaDEXAMPLETOKEN", signed_request.headers["x-amz-security-token"])
    end)

end)

describe("Error handling", function()

    it("should return error when required parameters are missing", function()
        local result, err = aws_signature.sign_request({})
        assert.is_nil(result)
        assert.is_not_nil(err)
        assert.matches("Missing required parameter", err)
    end)

    it("should return error when Host header is missing", function()
        local result, err = aws_signature.sign_request({
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225"
        })
        assert.is_nil(result)
        assert.is_not_nil(err)
        assert.matches("Missing required.*Host", err)
    end)

end)

describe("Custom header signing", function()

    it("should sign custom headers when specified", function()
        local opts = {
            method = "PUT",
            uri = "/test.txt",
            headers = {
                Host = "my-bucket.s3.amazonaws.com",
                ["Content-Type"] = "text/plain",
                ["X-Custom-Header"] = "custom-value"
            },
            signed_headers = {"content-type"},  -- Request to sign content-type
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225"
        }

        local signed_request, err = aws_signature.sign_request(opts)
        assert.is_nil(err)
        assert.is_not_nil(signed_request)

        -- Verify content-type is in the SignedHeaders list
        local auth_header = signed_request.headers["Authorization"]
        assert.matches("content%-type", auth_header)
    end)

end)

describe("Presigned URLs", function()

    it("should generate presigned URL for S3 GET request", function()
        local opts = {
            method = "GET",
            uri = "/test.txt",
            host = "my-bucket.s3.us-east-1.amazonaws.com",
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225",
            expires = 3600
        }

        local url, err = aws_signature.presign_url(opts)
        assert.is_nil(err)
        assert.is_not_nil(url)
        assert.matches("https://", url)
        assert.matches("X%-Amz%-Algorithm=AWS4%-HMAC%-SHA256", url)
        assert.matches("X%-Amz%-Credential=", url)
        assert.matches("X%-Amz%-Date=", url)
        assert.matches("X%-Amz%-Expires=3600", url)
        assert.matches("X%-Amz%-SignedHeaders=host", url)
        assert.matches("X%-Amz%-Signature=", url)
    end)

    it("should include session token in presigned URL", function()
        local opts = {
            method = "GET",
            uri = "/test.txt",
            host = "my-bucket.s3.us-east-1.amazonaws.com",
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            session_token = "EXAMPLETOKEN123",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225",
            expires = 300
        }

        local url, err = aws_signature.presign_url(opts)
        assert.is_nil(err)
        assert.is_not_nil(url)
        assert.matches("X%-Amz%-Security%-Token=EXAMPLETOKEN123", url)
    end)

    it("should return error for expires > 7 days", function()
        local opts = {
            method = "GET",
            uri = "/test.txt",
            host = "my-bucket.s3.us-east-1.amazonaws.com",
            service = "s3",
            region = "us-east-1",
            access_key = "ASIAUZABC123456",
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_iso8601 = "20250225T215924Z",
            date_stamp = "20250225",
            expires = 700000  -- More than 7 days
        }

        local url, err = aws_signature.presign_url(opts)
        assert.is_nil(url)
        assert.is_not_nil(err)
        assert.matches("604800", err)
    end)

end)

describe("Date generation helper", function()

    it("should generate ISO8601 and date stamp", function()
        local dates = aws_signature.generate_dates()
        assert.is_not_nil(dates)
        assert.is_not_nil(dates.iso8601)
        assert.is_not_nil(dates.stamp)

        -- Check format
        assert.matches("^%d%d%d%d%d%d%d%dT%d%d%d%d%d%dZ$", dates.iso8601)
        assert.matches("^%d%d%d%d%d%d%d%d$", dates.stamp)
    end)

    it("should accept custom timestamp", function()
        local fixed_time = 1640995200  -- 2022-01-01 00:00:00 UTC
        local dates = aws_signature.generate_dates(fixed_time)

        assert.are.equal("20220101T000000Z", dates.iso8601)
        assert.are.equal("20220101", dates.stamp)
    end)

end)

describe("S3 POST policy signing", function()

    it("should sign S3 POST policy", function()
        local policy_json = '{"expiration":"2025-12-31T12:00:00.000Z","conditions":[{"bucket":"my-bucket"}]}'

        local result, err = aws_signature.sign_post_policy({
            policy = policy_json,
            secret_key = "5wfFi0FEaaaaacccc1111111111111/",
            date_stamp = "20250225",
            region = "us-east-1"
        })

        assert.is_nil(err)
        assert.is_not_nil(result)
        assert.is_not_nil(result.policy)
        assert.is_not_nil(result.signature)

        -- Policy should be base64 encoded
        assert.is_string(result.policy)
        -- Signature should be hex
        assert.matches("^%x+$", result.signature)
    end)

    it("should return error when policy is missing", function()
        local result, err = aws_signature.sign_post_policy({
            secret_key = "test",
            date_stamp = "20250225",
            region = "us-east-1"
        })

        assert.is_nil(result)
        assert.is_not_nil(err)
        assert.matches("Missing required parameter: policy", err)
    end)

end)
