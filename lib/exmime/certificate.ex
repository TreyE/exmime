defmodule Exmime.Certificate do
  require Exmime.Records

  def extract_rsa_public_key(decoded_cert_pem) do
    extract_tbs_cert(decoded_cert_pem) |>
      extract_tbs_pubkey_info |>
        extract_rsa_keyinfo_pubkey
  end

  def extract_serial_number(decoded_cert_pem) do
    extract_tbs_cert(decoded_cert_pem) |>
      extract_tbs_serial_number
  end

  defp extract_tbs_cert(decoded_cert_pem) do
    Exmime.Records.'Certificate'(
      decoded_cert_pem,
      :tbsCertificate
    )
  end

  defp extract_tbs_serial_number(tbs_cert) do
    Exmime.Records.'TBSCertificate'(
      tbs_cert,
      :serialNumber
    )
  end

  defp extract_tbs_pubkey_info(tbs_cert) do
    Exmime.Records.'TBSCertificate'(
      tbs_cert,
      :subjectPublicKeyInfo
    )
  end

  defp extract_rsa_keyinfo_pubkey(s_pki) do
    pkey = Exmime.Records.'SubjectPublicKeyInfo'(
      s_pki,
      :subjectPublicKey
    )
    decode_public_key_asn1(pkey)
  end

  defp decode_public_key_asn1(bin) do
    {_, data} = Exmime.Asn1Dynamic.decode_asn1(bin)
    data
  end
end
