defmodule Exmime.Asn1.ContentInfoTest do
  use ExUnit.Case
  doctest Exmime.Asn1.ContentInfo

  require Exmime.Records

  test "decode for aes cbc 256 rsa" do
    {cert_serial, rsa_pubkey_record} = Exmime.RsaTestHelpers.extract_cert_props()
    data = "A TEST MESSAGE 1\nA TEST MESSAGE 2\nA TEST MESSAGE 3"
    content_info = Exmime.single_recipient_rsa_aes_cbc(cert_serial, rsa_pubkey_record, 256, data)
    encoded_content = Exmime.PemEncoder.encode_content_info(content_info)
    pem_binary = :public_key.pem_encode([encoded_content])
    {:ok, out_f} = :file.open("ci_decode_test_file_scratch.pkcs7", [:binary, :write])
    IO.binwrite(out_f, pem_binary)
    :file.close(out_f)
    p_key = Exmime.RsaTestHelpers.read_private_key()
    {:ok, f} = :file.open("ci_decode_test_file_scratch.pkcs7", [:binary, :read])
    new_stream = Exmime.PemStreamReader.new_from_io(f)
    f_stream = Exmime.PemStreamReader.wrap_as_file(new_stream)
    ci = Exmime.Asn1.ContentInfo.decode_stream(f_stream, 0, new_stream.octet_length)
    message_recipient_decoding_instructions = %Exmime.MessageRecipients.DecodingInstructions{
      private_key: p_key,
      serial_number: cert_serial,
      issuer: {:rdnSequence, []}
    }
    {:ok, decoded_stream} = Exmime.Asn1.EnvelopedData.decrypt_stream(ci, message_recipient_decoding_instructions)
    decoded_data = Enum.reduce(decoded_stream, <<>>, fn(e, acc) -> acc <> e end)
    ^data = decoded_data
    File.rm!("ci_decode_test_file_scratch.pkcs7")
  end
end
