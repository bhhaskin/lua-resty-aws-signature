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
        local signed_request = aws_signature.sign_request(opts)
        local expected_signature = "e8b048d6e435351ab14e71a097a58e5796fd35822a7e3a463a071d168493d55c"

        local computed_signature = signed_request.headers["Authorization"]:match("Signature=(%w+)")
        
        assert.is_not_nil(computed_signature, "Signature not found in Authorization header")
        assert.are.equal(expected_signature, computed_signature)
    end)

end)
