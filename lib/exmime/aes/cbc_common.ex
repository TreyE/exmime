defmodule Exmime.Aes.CbcCommon do
  def generate_parameters() do
    :crypto.strong_rand_bytes(16)
  end

  def split_and_return_without_padding(<<>>) do
    <<>>
  end

  def split_and_return_without_padding(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end

  def padding_data(data_length, b_size) do
    rem_bytes = rem(data_length,b_size)
    Exmime.Padding.Pkcs7Padding.provide_padding_of_length(b_size - rem_bytes)
  end
end
