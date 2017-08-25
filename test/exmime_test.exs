defmodule ExmimeTest do
  use ExUnit.Case
  doctest Exmime

  require Exmime.Records

  test "content info for aes cbc 256 rsa" do
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
    aes_key = :crypto.strong_rand_bytes(16)
    aes_iv = :crypto.strong_rand_bytes(16)
    data = "A TEST MESSAGE"
    content_info = Exmime.single_recipient_rsa_aes_256_cbc(cert_serial, rsa_pubkey_record, aes_key, aes_iv, data)
    IO.inspect content_info
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    IO.puts :public_key.pem_encode([encoded_content])
  end
end
