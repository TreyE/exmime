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
    {:asn1_OPENTYPE, <<_::big-unsigned-integer-size(8), ivec_size :: size(8), iv::binary>>} = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :parameters)
    iv
  end
end
