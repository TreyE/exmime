defmodule ExmimeTest do
  use ExUnit.Case
  doctest Exmime

  require Exmime.Records

  test "content info for aes cbc 256 rsa" do
    {cert_serial, rsa_pubkey_record} = extract_cert_props()
    data = "A TEST MESSAGE"
    content_info = Exmime.single_recipient_rsa_aes_cbc(cert_serial, rsa_pubkey_record, 256, data)
    IO.inspect content_info
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    IO.puts :public_key.pem_encode([encoded_content])
  end

  test "decode for aes cbc 256 rsa" do
    {cert_serial, rsa_pubkey_record} = extract_cert_props()
    data = "A TEST MESSAGE"
    content_info = Exmime.single_recipient_rsa_aes_cbc(cert_serial, rsa_pubkey_record, 256, data)
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    pem_binary = :public_key.pem_encode([encoded_content])
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
