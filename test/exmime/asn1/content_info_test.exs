defmodule Exmime.Asn1.ContentInfoTest do
  use ExUnit.Case
  doctest Exmime.Asn1.ContentInfo

  require Exmime.Records

  test "object decode" do
    {:ok, f} = :file.open("example.smime", [:binary, :read])
    #new_stream = Exmime.PemStreamReader.new_from_io(f)
    #f_stream = Exmime.PemStreamReader.wrap_as_file(new_stream)
    #IO.inspect Exmime.Asn1.ContentInfo.decode_stream(f_stream, 0, new_stream.octet_length)
  end

  test "decode for aes cbc 256 rsa" do
    {cert_serial, rsa_pubkey_record} = extract_cert_props()
    data = "A TEST MESSAGE 1\nA TEST MESSAGE 2\nA TEST MESSAGE 3"
    content_info = Exmime.single_recipient_rsa_aes_cbc(cert_serial, rsa_pubkey_record, 256, data)
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    pem_binary = :public_key.pem_encode([encoded_content])
    IO.inspect(pem_binary)
    {:ok, out_f} = :file.open("ci_decode_test_file_scratch.pkcs7", [:binary, :write])
    IO.binwrite(out_f, pem_binary)
    :file.close(out_f)
    {:ok, f} = :file.open("ci_decode_test_file_scratch.pkcs7", [:binary, :read])
    new_stream = Exmime.PemStreamReader.new_from_io(f)
    f_stream = Exmime.PemStreamReader.wrap_as_file(new_stream)
    p_key = read_private_key()
    ci = Exmime.Asn1.ContentInfo.decode_stream(f_stream, 0, new_stream.octet_length)
    decoded_stream = Exmime.decrypt_stream(p_key, ci)
    decoded_data = Enum.reduce(decoded_stream, <<>>, fn(e, acc) -> acc <> e end)
    IO.inspect(decoded_data)
    ^data = decoded_data
  end

  def read_private_key() do
    {:ok, f} = :file.open("example.com.key", [:binary, :read])
    {:ok, f_data} = :file.read(f, 82174)
    [entry] = :public_key.pem_decode(f_data)
    pem_entry = :public_key.pem_entry_decode(entry)
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
