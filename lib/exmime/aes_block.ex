defmodule Exmime.AesBlock do
  require Exmime.Records

  def block_encrypt(key, ivec, data) do
    :crypto.block_encrypt(:aes_cbc, key, ivec, data)
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

  def content_encryption_algorithm_identifier(key, ivec) do
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
