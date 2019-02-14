defmodule Exmime.AesBlock do
  require Exmime.Records

  defmodule AesBlockState do
    defstruct [:key, :last_ciphertext, :remaining_data]
  end

  def provides_algo?(algo_oid) do
    Enum.member?(Exmime.Aes.CbcAlgo.supported_algos(), algo_oid)
  end

  def extract_algo_params(eci) do
    Exmime.Aes.CbcAlgo.extract_algo_params(eci)
  end

  def extract_stream_algo_params(eci) do
    Exmime.Aes.CbcAlgo.extract_stream_algo_params(eci)
  end

  def decode_block(data, aes_key, params) do
    Exmime.Aes.CbcAlgo.decode_block(data, aes_key, params)
  end

  def decode_stream(f, start, len, aes_key, params) do
    Exmime.Aes.CbcAlgo.decode_stream(f, start, len, aes_key, params)
  end

  def generate_AES_parameters(key_size) do
    {:crypto.strong_rand_bytes(Kernel.trunc(key_size/8)), :crypto.strong_rand_bytes(16)}
  end

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

  defp content_encryption_algorithm_identifier(key, ivec) do
    algo_identifier = Exmime.Aes.CbcAlgo.algo_identifier(key)
    ivec_size = byte_size(ivec)
    Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(
      algorithm: algo_identifier,
      parameters: {:asn1_OPENTYPE, <<4::big-unsigned-integer-size(8), ivec_size :: size(8)>> <> ivec}
    )
  end

  def create_content_encryption_algorithm_identifier_binary(algo_identifier, ivec) do
    ivec_size = byte_size(ivec)
    cec = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(
      algorithm: algo_identifier,
      parameters: {:asn1_OPENTYPE, <<4::big-unsigned-integer-size(8), ivec_size :: size(8)>> <> ivec}
    )
    :'OTP-PUB-KEY'.encode(:'ContentEncryptionAlgorithmIdentifier', cec)
  end
end
