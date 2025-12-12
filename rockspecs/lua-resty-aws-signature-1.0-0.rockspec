package = "lua-resty-aws-signature"
version = "1.0-0"
source = {
   url = "https://github.com/bhhaskin/lua-resty-aws-signature/archive/refs/tags/v1.0-0.tar.gz",
   md5 = "44bb71d4ffa7f186ee5b829471845cc3",
   dir = "lua-resty-aws-signature-1.0-0"
}
description = {
   summary  = "AWS Signature V4 library for OpenResty with presigned URLs and POST policy support",
   detailed = [[
      lua-resty-aws-signature is a comprehensive AWS Signature Version 4 signing library
      for OpenResty. Features include header-based request signing, presigned URL generation,
      S3 POST policy signing, custom header signing, session token support for temporary
      credentials, automatic query string encoding/sorting, and comprehensive error handling.
   ]],
   homepage = "https://github.com/bhhaskin/lua-resty-aws-signature",
   license  = "MIT",
   maintainer = "Bryan Haskin <bhhaskin@bitsofsimplicity.com>"
}
dependencies = {
   "lua >= 5.1",
   "lua-resty-openssl"
}
build = {
   type = "builtin",
   modules = {
      ["resty.aws_signature"] = "src/resty/aws_signature.lua",
   }
}
