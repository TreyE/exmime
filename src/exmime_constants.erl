-module(exmime_constants).

-compile(export_all).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

envelopedData() -> ?envelopedData.

rsaEncryption() -> ?rsaEncryption.

aes_256_cbc() -> {2, 16, 840, 1, 101, 3, 4, 1, 42}.
aes_128_cbc() -> {2, 16, 840, 1, 101, 3, 4, 1, 2}.

data() -> ?data.

%% Stolen from generated code

e_object_identifier({'OBJECT IDENTIFIER',V}) ->
    e_object_identifier(V);
e_object_identifier(V) when is_tuple(V) ->
    e_object_identifier(tuple_to_list(V));
e_object_identifier([E1,E2|Tail]) ->
    Head = 40 * E1 + E2,
    {H,Lh} = mk_object_val(Head),
    {R,Lr} = lists:mapfoldl(fun enc_obj_id_tail/2, 0, Tail),
    {[H|R],Lh + Lr}.

enc_obj_id_tail(H, Len) ->
    {B,L} = mk_object_val(H),
    {B,Len + L}.

mk_object_val(0, Ack, Len) ->
    {Ack,Len};
mk_object_val(Val, Ack, Len) ->
    mk_object_val(Val bsr 7, [Val band 127 bor 128|Ack], Len + 1).

mk_object_val(Val) when Val =< 127 ->
    {[255 band Val],1};
mk_object_val(Val) ->
    mk_object_val(Val bsr 7, [Val band 127], 1).