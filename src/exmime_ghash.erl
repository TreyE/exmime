-module(exmime_ghash).

-export([gcm_ghash_final_block/4, gcm_ghash_multiply/2, gcm_pad/1]).

%% Shamelessly stolen from:
%%   https://github.com/potatosalad/erlang-jose
%% All credit goes there.

%% @private
gcm_ghash_multiply(GHash, K) ->
	gcm_ghash_multiply(0, K, crypto:bytes_to_integer(GHash), 0).

%% @private
gcm_ghash_multiply(16, _K, _GHash, Result) ->
	<< Result:128/unsigned-big-integer-unit:1 >>;
gcm_ghash_multiply(I, K, GHash, Result) ->
	J = (GHash band 16#FF),
	Val = gf_2_128_mul(K, (J bsl (I * 8))),
	gcm_ghash_multiply(I + 1, K, GHash bsr 8, Result bxor Val).

%% @private
gcm_pad(Binary) when (byte_size(Binary) rem 16) =/= 0 ->
	PadBits = (16 - (byte_size(Binary) rem 16)) * 8,
	<< Binary/binary, 0:PadBits >>;
gcm_pad(Binary) ->
	Binary.

%% @private
gf_2_128_mul(X, Y) ->
	gf_2_128_mul(127, X, Y, 0).

%% @private
gf_2_128_mul(-1, _X, _Y, R) ->
	R;
gf_2_128_mul(I, X0, Y, R0) ->
	R1 = (R0 bxor (X0 * ((Y bsr I) band 1))),
	X1 = (X0 bsr 1) bxor ((X0 band 1) * 16#E1000000000000000000000000000000),
	gf_2_128_mul(I - 1, X1, Y, R1).

gcm_ghash_final_block(K, AADBits, CipherTextBits, GHash) ->
	GHashMask = << ((AADBits bsl 64) bor CipherTextBits):128/unsigned-big-integer-unit:1 >>,
	gcm_ghash_multiply(crypto:exor(GHash, GHashMask), K).