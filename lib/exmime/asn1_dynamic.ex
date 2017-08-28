defmodule Exmime.Asn1Dynamic do
  def decode_asn1(<<48::unsigned-big-integer-size(8),1::size(1), len::unsigned-big-integer-size(7), rest::binary>>) do
    {len_val, remaining_data} = read_len_bytes(rest, len)
    {<<>>, parse_sequence_items(len_val, remaining_data)}
  end

  def decode_asn1(<<48::unsigned-big-integer-size(8),len::integer-size(8), rest::binary>>) do
    {<<>>, parse_sequence_items(len, rest)}
  end

  def decode_asn1(<<2::unsigned-integer-size(8), 1::unsigned-big-integer-size(1), len::unsigned-big-integer-size(7), rest::binary>>) do
    {len_val, remaining_data} = read_len_bytes(rest, len)
    bit_count = len_val * 8
    <<value::signed-big-integer-size(bit_count), remaining::binary>> = remaining_data
    {remaining, value}
  end

  def decode_asn1(<<2::unsigned-integer-size(8), len::unsigned-big-integer-size(8), rest::binary>>) do
    bit_count = len * 8
    <<value::signed-big-integer-size(bit_count), remaining::binary>> = rest
    {remaining, value}
  end

  defp read_len_bytes(data, len_byte_count) do
    bit_count = len_byte_count * 8
    <<len_val::unsigned-big-integer-size(bit_count), rest::binary>> = data
    {len_val, rest}
  end

  defp parse_sequence_items(len, data) do
    <<sequence_binary::binary-size(len), _::binary>> = data
    read_sequence_items(sequence_binary, [])
  end

  defp read_sequence_items(<<>>, list) do
    Enum.reverse(list)
  end

  defp read_sequence_items(sequence_data, list) do
    {rest, item} = decode_asn1(sequence_data)
    read_sequence_items(rest, [item|list])
  end
end
