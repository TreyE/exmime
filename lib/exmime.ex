defmodule Exmime do
  def single_recipient_rsa_aes_cbc(cert_serial_number, rsa_public_key, aes_key_size, data) do
    {aes_key, aes_iv} = Exmime.AesBlock.generate_AES_parameters(aes_key_size)
    recipient_info = Exmime.RecipientInfo.rsa_recipient_info(cert_serial_number, rsa_public_key, aes_key)
    eci = Exmime.AesBlock.encrypted_content_info(aes_key, aes_iv, data)
    Exmime.EnvelopedData.content_info([recipient_info], eci)
  end

  def decrypt_rsa(priv_key, content_info) do
    ris = Exmime.RecipientInfo.decode_content_info_recipient_infos(content_info)
    eci = Exmime.EnvelopedData.decode_content_info_encrypted_content_info(content_info)
    e_module = Exmime.EncryptedContentInfo.encryption_module(eci)
    encrypted_data = Exmime.EncryptedContentInfo.decode_encrypted_content_info_data(eci)
    algo_params = e_module.extract_algo_params(eci) 
    session_key = Exmime.RecipientInfo.extract_recipient_session_key(priv_key, ris)
    Exmime.AesBlock.decode_aes_block(encrypted_data, session_key, algo_params)
  end
end
