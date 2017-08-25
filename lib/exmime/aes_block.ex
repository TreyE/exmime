defmodule Exmime.AesBlock do
  require Exmime.Records

  defmodule AesBlockState do
    defstruct [:key, :last_ciphertext, :remaining_data]
  end

  def block_encrypt(key, ivec, data) do
    :crypto.block_encrypt(:aes_cbc, key, ivec, data)
  end

  def stream_encrypt(key, ivec, data) do
    stream = aes_256_stream(key, ivec, data)
    Enum.reduce(stream, <<>>, fn(d, acc) ->
      acc <> d
    end)
  end

  def encrypted_content_info(key, ivec, data) do
    ceai = content_encryption_algorithm_identifier(key, ivec)
    pad_data = :pkcs7.pad(data)
    encrypted_data = block_encrypt(key, ivec, pad_data)
    Exmime.Records.'EncryptedContentInfo'(
      contentType: :exmime_constants.data(),
      contentEncryptionAlgorithm: ceai,
      encryptedContent: encrypted_data
    )
  end

  defp aes_256_stream(key, ivec, data) do
    Stream.unfold(%AesBlockState{key: key, last_ciphertext: ivec, remaining_data: data}, &aes_256_single_step/1)
  end

  defp aes_256_single_step(%AesBlockState{remaining_data: <<>>}) do
    nil
  end

  defp aes_256_single_step(%AesBlockState{remaining_data: <<data::size(256), rest>>} = state) do
    key = state.key
    ivec = state.last_ciphertext
    new_ciphertext = :crypto.block_encrypt(:aes_cbc, key, ivec, data)
    {new_ciphertext, %AesBlockState{state | remaining_data: rest, last_ciphertext: new_ciphertext}}
  end

  defp aes_256_single_step(%AesBlockState{remaining_data: data} = state) do
    pad_data = :pkcs7.pad(data)
    key = state.key
    ivec = state.last_ciphertext
    new_ciphertext = :crypto.block_encrypt(:aes_cbc, key, ivec, pad_data)
    {new_ciphertext, %AesBlockState{state | remaining_data: <<>>, last_ciphertext: new_ciphertext}}
  end

  defp content_encryption_algorithm_identifier(key, ivec) do
    algo_identifier = case byte_size(key) do
      32 -> :exmime_constants.aes_256_cbc()
      _ -> :exmime_constants.aes_128_cbc()
    end
    ivec_size = byte_size(ivec)
    Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(
      algorithm: algo_identifier,
      parameters: {:asn1_OPENTYPE, <<4, ivec_size :: size(8)>> <> ivec}
    )
  end
end
