defmodule Exmime.Padding.Pkcs7Padding do
  def provide_padding_of_length(len) when (len > 0) and (len <= 255) do
    :binary.copy(:binary.encode_unsigned(len), len)
  end
end
