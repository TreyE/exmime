-module(exmime_constants).

-compile(export_all).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

envelopedData() -> ?envelopedData.

rsaEncryption() -> ?rsaEncryption.

aes_256_cbc() -> {2, 16, 840, 1, 101, 3, 4, 1, 42}.
aes_128_cbc() -> {2, 16, 840, 1, 101, 3, 4, 1, 2}.

data() -> ?data.
