defmodule Exmime.AesBlock do
  require Exmime.Records

  defmodule AesBlockState do
    defstruct [:key, :last_ciphertext, :remaining_data]
  end

  def provides_algo?(algo_oid) do
    Enum.member?([:exmime_constants.aes_256_cbc(), :exmime_constants.aes_128_cbc()], algo_oid)
  end

  def extract_algo_params(eci) do
    ceai = Exmime.Records.'EncryptedContentInfo'(eci, :contentEncryptionAlgorithm)
    {:asn1_OPENTYPE, <<_::big-unsigned-integer-size(8), ivec_size :: size(8), iv::binary>>} = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :parameters)
    iv
  end

  def decode_aes_block(data, aes_key, params) do
    :crypto.block_decrypt(:aes_cbc, aes_key, params, data) |>
      :pkcs7.unpad
  end

  def generate_AES_parameters(key_size) do
    {:crypto.strong_rand_bytes(Kernel.trunc(key_size/8)), :crypto.strong_rand_bytes(16)}
  end

  def block_encrypt(key, ivec, data) do
    :crypto.block_encrypt(:aes_cbc, key, ivec, data)
  end

  def stream_encrypt(key, ivec, data) do
    aes_256_stream(key, ivec, data)
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

  defp aes_256_single_step(%AesBlockState{remaining_data: <<data::binary-size(16), rest::binary>>} = state) do
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
      parameters: {:asn1_OPENTYPE, <<4::big-unsigned-integer-size(8), ivec_size :: size(8)>> <> ivec}
    )
  end
end
