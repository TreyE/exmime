defmodule Exmime.EncryptedContentInfo do
  require Exmime.Records

  def decode_encrypted_content_info_data(eci) do
    Exmime.Records.'EncryptedContentInfo'(eci, :encryptedContent)
  end

  def encryption_module(eci) do
    ceai = Exmime.Records.'EncryptedContentInfo'(eci, :contentEncryptionAlgorithm)
    select_algorithm_module(ceai)
  end

  def select_algorithm_module(ceai) do
    algo_oid = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :algorithm)
    case Exmime.AesBlock.provides_algo?(algo_oid) do
      false -> nil
      _ -> Exmime.AesBlock
    end
  end
end
