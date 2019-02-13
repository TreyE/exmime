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
    e_module.decode_block(encrypted_data, session_key, algo_params)
  end

  def decrypt_stream(priv_key, %Exmime.Asn1.EnvelopedData{recipient_infos: [ris|_], encrypted_content_info: eci}) do
    e_module = Exmime.EncryptedContentInfo.select_algorithm_module(eci.content_encryption_algorithm)
    algo_params = e_module.extract_stream_algo_params(eci)
    encrypted_key = ris.encrypted_key
    session_key = :public_key.decrypt_private(encrypted_key, priv_key)
    {:file_stream, f, pos, len} = eci.encrypted_content
    e_module.decode_stream(f, pos, len, session_key, algo_params)
  end
end
