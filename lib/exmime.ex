defmodule Exmime do
  def single_recipient_rsa_aes_256_cbc(cert_serial_number, rsa_public_key, aes_key, aes_iv, data) do
    recipient_info = Exmime.RecipientInfo.rsa_recipient_info(cert_serial_number, rsa_public_key, aes_key)
    eci = Exmime.AesBlock.encrypted_content_info(aes_key, aes_iv, data)
    Exmime.EnvelopedData.content_info([recipient_info], eci)
  end
end
