defmodule Exmime.Aes.Cbc256 do
  require Exmime.Records

  def padding_data(data_length) do
    Exmime.Aes.CbcCommon.padding_data(data_length, 16)
  end

  def create_content_encryption_algorithm_identifier_binary(params) do
    Exmime.AesBlock.create_content_encryption_algorithm_identifier_binary(:exmime_constants.aes_256_cbc(),params)
  end

  def generate_parameters(session_key) do
    Exmime.Aes.CbcCommon.generate_parameters(session_key)
  end

  def generate_key() do
    :crypto.strong_rand_bytes(32)
  end

  def block_encrypt(key, params, data) do
    :crypto.block_encrypt(:aes_cbc256, key, params, data)
  end

  def extract_stream_algo_params(eci) do
    ceai = eci.content_encryption_algorithm
    {:asn1_OPENTYPE, <<_::big-unsigned-integer-size(8), _ :: size(8), iv::binary>>} = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :parameters)
    iv
  end

  def decode_stream(f, start, _, s_key, params) do
    with({:ok, _} <- :file.position(f, start)) do
      decoder_stream(f, s_key, params, 16)
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
      :eof -> {[Exmime.Aes.CbcCommon.split_and_return_without_padding(buff)], {:eof,f}}
      data ->
        new_data = :crypto.block_decrypt(:aes_cbc256, k, ivec, data)
        case (byte_size(buff) > 0) do
          false -> {[<<>>], {k, b_size, data, f, new_data}}
          _ -> {[buff], {k, b_size, data, f, new_data}}
        end
    end
  end
end
