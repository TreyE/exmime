defmodule ExmimeTest do
  use ExUnit.Case
  doctest Exmime

  require Exmime.Records

  test "decode for aes cbc 256 rsa" do
    {cert_serial, rsa_pubkey_record} = extract_cert_props()
    data = "A TEST MESSAGE"
    content_info = Exmime.single_recipient_rsa_aes_cbc(cert_serial, rsa_pubkey_record, 256, data)
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    pem_binary = :public_key.pem_encode([encoded_content])
    [encoded_entry] = :public_key.pem_decode(pem_binary)
    encrypted_content_info = :public_key.pem_entry_decode(encoded_entry)
    p_key = read_private_key()
    decoded_data = Exmime.decrypt_rsa(p_key, encrypted_content_info)
    ^data = decoded_data
  end

  test "decode for aes cbc 128 rsa" do
    {cert_serial, rsa_pubkey_record} = extract_cert_props()
    data = "A TEST MESSAGE"
    content_info = Exmime.single_recipient_rsa_aes_cbc(cert_serial, rsa_pubkey_record, 128, data)
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    pem_binary = :public_key.pem_encode([encoded_content])
    [encoded_entry] = :public_key.pem_decode(pem_binary)
    encrypted_content_info = :public_key.pem_entry_decode(encoded_entry)
    p_key = read_private_key()
    decoded_data = Exmime.decrypt_rsa(p_key, encrypted_content_info)
    ^data = decoded_data
  end

  def read_private_key() do
    {:ok, f} = :file.open("example.com.key", [:binary, :read])
    {:ok, f_data} = :file.read(f, 82174)
    [entry] = :public_key.pem_decode(f_data)
    :public_key.pem_entry_decode(entry)
  end

  def extract_cert_props() do
    {:ok, f} = :file.open("example.com.crt", [:binary, :read])
    {:ok, f_data} = :file.read(f, 82174)
    [entry] = :public_key.pem_decode(f_data)
    pem_entry = :public_key.pem_entry_decode(entry)
    cert_serial = Exmime.Certificate.extract_serial_number(pem_entry)
    [modulus, public_exp] = Exmime.Certificate.extract_rsa_public_key(pem_entry)
    rsa_pubkey_record = Exmime.Records.'RSAPublicKey'(
      modulus: modulus,
      publicExponent: public_exp
    )
    {cert_serial, rsa_pubkey_record}
  end
end
