defmodule Exmime.Asn1.StreamingBerEncoder do

  require Exmime.Asn1.EncodingMacros

  def wrap_item(item_type_binary, item_binary, item_length) do
    item_len_bytes = encode_length_value(item_length)
    bin = item_type_binary <> item_len_bytes <> item_binary
    {item_length + byte_size(item_len_bytes) + byte_size(item_type_binary), bin}
  end

  def encode_object_id(oid) do
    {oid_bin_list, oid_length} = :exmime_constants.e_object_identifier(oid)
    oid_bin = Enum.reduce(oid_bin_list, <<>>, fn(e, acc) -> acc <> encode_oid_parts(e) end)
    oid_len_bytes = encode_length_value(oid_length)
    <<6::integer-size(8)>> <> oid_len_bytes <> oid_bin
  end

  defp encode_oid_parts(a) when is_binary(a) do
    a
  end

  defp encode_oid_parts(a) when is_list(a) do
    Enum.reduce(a, <<>>, fn(e, acc) -> acc <> <<e::integer-size(8)>> end)
  end

  def encode_length_value(len) when len < 128 do
    <<len::integer-size(8)>>
  end

  def encode_length_value(len) when len < 256 do
    asn1_len_bytes_for(0, len, <<129::integer-size(8)>>)
  end

  Exmime.Asn1.EncodingMacros.define_length_encoding_functions()

  def encode_length_value(_) do
    {:error, :asn1_length_too_big}
  end

  defp asn1_len_bytes_for(0, len, bin) do
    bin <> <<len::integer-size(8)>>
  end

  defp asn1_len_bytes_for(radix, len, bin) do
    val = div(len,trunc(:math.pow(256,radix)))
    asn1_len_bytes_for(radix - 1, len - val, bin <> <<val::integer-size(8)>>)
  end
end
