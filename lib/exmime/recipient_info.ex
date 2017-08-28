defmodule Exmime.RecipientInfo do
  require Exmime.Records

  def rsa_recipient_info(cert_serial_number, rsa_public_key, session_key) do
    kea = Exmime.Records.'KeyEncryptionAlgorithmIdentifier'(
      algorithm: :exmime_constants.rsaEncryption(),
      parameters: {:asn1_OPENTYPE, <<5, 0>>}
    )
    issuer_and_serial_number = Exmime.Records.'IssuerAndSerialNumber'(
      issuer: {:rdnSequence, []},
      serialNumber: cert_serial_number
    )
    encrypted_key = :public_key.encrypt_public(session_key, rsa_public_key)
    Exmime.Records.'RecipientInfo'(
      version: :riVer0,
      issuerAndSerialNumber: issuer_and_serial_number,
      keyEncryptionAlgorithm: kea,
      encryptedKey: encrypted_key
    )
  end

  def decode_content_info_recipient_infos(content_info) do
    content = Exmime.Records.'ContentInfo'(content_info, :content)
    {_, ris} = Exmime.Records.'EnvelopedData'(content, :recipientInfos)
    ris
  end

  def extract_recipient_session_key(rsa_private_key, [r_info|_]) do
    :public_key.decrypt_private(extract_recipient_info_encrypted_key(r_info), rsa_private_key) 
  end

  defp extract_recipient_info_encrypted_key(r_info) do
    Exmime.Records.'RecipientInfo'(r_info, :encryptedKey)
  end
end
