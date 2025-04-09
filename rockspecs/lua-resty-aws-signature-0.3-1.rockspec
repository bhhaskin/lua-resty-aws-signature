package = "lua-resty-aws-signature"
version = "0.3-1"
source = {
   url = "https://github.com/bhhaskin/lua-resty-aws-signature/archive/refs/tags/v0.3-1.tar.gz",
    md5 = "b42edf2b0363f83c2ebb4e97b86142e5",
   dir = "lua-resty-aws-signature-0.3-1"
}
description = {
   summary  = "AWS signature V4 library for OpenResty ",
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
