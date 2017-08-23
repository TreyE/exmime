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
end
