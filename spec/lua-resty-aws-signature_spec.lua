local aws_signature = require("resty.aws_signature")

describe("AWS Signature v4", function()

    local opts = {
        method = "GET",
        uri = "/Prod/hello",
        query_string = "",
        headers = {
            Host = "myapi123.execute-api.us-east-1.amazonaws.com",
            ["x-amz-date"] = "20250225T155154Z"
        },
        payload = "",
        service = "execute-api",
        region = "us-east-1",
        access_key = "ASIAUZABC123456",
        secret_key = "5wfFi0FEaaaaacccc1111111111111",
        date_iso8601 = "20250225T155154Z",
        date_stamp = "20250225"
    }

    it("should generate the correct Authorization header", function()
        local signed_request = aws_signature.sign_request(opts)
        local expected_signature = "636ad54617ef4c706fee451c9ca953c8316e3c0d215b5cda769413eaeceea2d2"

        local computed_signature = signed_request.headers["Authorization"]:match("Signature=(%w+)")
        
        assert.is_not_nil(computed_signature, "Signature not found in Authorization header")
        assert.are.equal(expected_signature, computed_signature)
    end)

end)

describe("AWS Signature v4 for S3", function()

    local opts = {
        method = "GET",
        uri = "/test.txt",
        query_string = "",
        headers = {
            Host = "my-bucket.s3.amazonaws.com",
            ["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ["x-amz-date"] = "20250225T155154Z"
        },
        payload = "",
        service = "s3",
        region = "us-east-1",
        access_key = "ASIAUZABC123456",
        secret_key = "5wfFi0FEaaaaacccc1111111111111",
        date_iso8601 = "20250225T155154Z",
        date_stamp = "20250225"
    }

    it("should generate the correct Authorization header for S3", function()
        local signed_request = aws_signature.sign_request(opts)
        local expected_signature = "444ef5a4d6aede0639c4e11d0bcda47b4c5a688e6ed9ceae69b3087aa862377f"

        local computed_signature = signed_request.headers["Authorization"]:match("Signature=(%w+)")
        
        assert.is_not_nil(computed_signature, "Signature not found in Authorization header")
        assert.are.equal(expected_signature, computed_signature)
    end)

end)
