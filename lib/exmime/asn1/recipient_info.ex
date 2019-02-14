defmodule Exmime.Asn1.RecipientInfo do
  defstruct [
    issuer_and_serial_number: nil,
    key_encryption_algorithm_identifier: nil,
    encrypted_key: nil
  ]

  require Exmime.Records

  def decode_binary(data) do
    with({:ok, ri} <- :'OTP-PUB-KEY'.decode(:'RecipientInfo', data)) do
      decode_record_parts(ri)
    end
  end

  defp decode_record_parts(ri) do
    iasn = Exmime.Records.'RecipientInfo'(ri, :issuerAndSerialNumber)
    keai = Exmime.Records.'RecipientInfo'(ri, :keyEncryptionAlgorithm)
    ek = Exmime.Records.'RecipientInfo'(ri, :encryptedKey)
    %__MODULE__{
      issuer_and_serial_number: Exmime.Asn1.IssuerAndSerialNumber.decode_record_parts(iasn),
      key_encryption_algorithm_identifier: decode_key_encryption_algorithm_identifier(keai),
      encrypted_key: ek
    }
  end

  defp decode_key_encryption_algorithm_identifier(keai) do
    kea = Exmime.Records.'KeyEncryptionAlgorithmIdentifier'(keai, :algorithm)
    params = Exmime.Records.'KeyEncryptionAlgorithmIdentifier'(keai, :parameters)
    %{
      algorithm: kea,
      parameters: params
    }
  end

  def create_recipient_info_binary(pub_key, session_key, cert_serial_number) do
    ek = :public_key.encrypt_public(session_key, pub_key)
    issuer_and_serial_number = Exmime.Records.'IssuerAndSerialNumber'(
      issuer: {:rdnSequence, []},
      serialNumber: cert_serial_number
    )
    kea = Exmime.Records.'KeyEncryptionAlgorithmIdentifier'(
      algorithm: :exmime_constants.rsaEncryption(),
      parameters: {:asn1_OPENTYPE, <<5, 0>>}
    )
    Exmime.Records.'RecipientInfo'(
      version: :riVer0,
      encryptedKey: ek,
      keyEncryptionAlgorithm: kea,
      issuerAndSerialNumber: issuer_and_serial_number
    )
  end

  def create_recipient_info_sequence_binaries(ris) do
    {:ok, ris_binaries} = :'OTP-PUB-KEY'.encode(:'RecipientInfos', {:riSequence, ris})
    {byte_size(ris_binaries) + Enum.count(ris), ris_binaries}
  end
end
