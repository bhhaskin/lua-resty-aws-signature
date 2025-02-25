local aws_signature = require("resty.aws_signature")

describe("lua-resty-aws-signature version check", function()
    it("should have a valid LuaRocks version number", function()
        assert.is_not_nil(aws_signature._VERSION)   -- Ensure _VERSION exists
        assert.is_string(aws_signature._VERSION)    -- Ensure it's a string
        assert.matches("^%d+%.%d+%-%d+$", aws_signature._VERSION) -- Check format X.Y-Z
    end)
end)