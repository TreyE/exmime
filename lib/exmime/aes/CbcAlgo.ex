defmodule Exmime.Aes.CbcAlgo do
  require Exmime.Records

  def supported_algos() do
    [:exmime_constants.aes_256_cbc(), :exmime_constants.aes_128_cbc()]
  end

  def algo_identifier(key) do
    case byte_size(key) do
      32 -> :exmime_constants.aes_256_cbc()
      _ -> :exmime_constants.aes_128_cbc()
    end
  end

  def decode_block(data, aes_key, params) do
    :crypto.block_decrypt(:aes_cbc, aes_key, params, data) |>
      :pkcs7.unpad
  end

  def extract_algo_params(eci) do
    ceai = Exmime.Records.'EncryptedContentInfo'(eci, :contentEncryptionAlgorithm)
    {:asn1_OPENTYPE, <<_::big-unsigned-integer-size(8), _ :: size(8), iv::binary>>} = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :parameters)
    iv
  end

  def extract_stream_algo_params(eci) do
    ceai = eci.content_encryption_algorithm
    {:asn1_OPENTYPE, <<_::big-unsigned-integer-size(8), _ :: size(8), iv::binary>>} = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :parameters)
    iv
  end

  def decode_stream(f, start, _, aes_key, params) do
    with({:ok, _} <- :file.position(f, start)) do
      decoder_stream(f, aes_key, params, 16)
    end
  end

  defp decoder_stream(f, key, ivec, b_size) do
    Stream.resource(
      fn() -> {key, b_size, ivec, f, <<>>} end,
      fn(a) ->
        read_my_data(a)
      end,
      fn(acc) -> acc end
    )
  end

  defp read_my_data({:eof, f}) do
    {:halt, f}
  end

  defp read_my_data({k, b_size, ivec, f, buff}) do
    case IO.binread(f, b_size) do
      {:error, reason} -> {:halt, {:error, reason}}
      :eof -> {[split_and_return_without_padding(buff)], {:eof,f}}
      data ->
        new_data = :crypto.block_decrypt(:aes_cbc256, k, ivec, data)
        case (byte_size(buff) > 0) do
          false -> {[<<>>], {k, b_size, data, f, new_data}}
          _ -> {[buff], {k, b_size, data, f, new_data}}
        end
    end
  end

  defp split_and_return_without_padding(<<>>) do
    <<>>
  end

  defp split_and_return_without_padding(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end
end
