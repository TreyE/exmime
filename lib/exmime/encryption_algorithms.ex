defmodule Exmime.EncryptionAlgorithms do

  require Exmime.Records

  def block_decryption_module(ceai) do
    algo_oid = Exmime.Records.'ContentEncryptionAlgorithmIdentifier'(ceai, :algorithm)
    aes_256_cbc = :exmime_constants.aes_256_cbc()
    case algo_oid do
      ^aes_256_cbc -> {:ok, Exmime.Aes.Cbc256}
      _ -> {:error, :unsupported_block_decryption_algorithm}
    end
  end

  def block_encryption_module(:aes_cbc256) do
    {:ok, Exmime.Aes.Cbc256}
  end

  def block_encryption_module(_) do
    {:error, :unsupported_block_encryption_algorithm}
  end
end
