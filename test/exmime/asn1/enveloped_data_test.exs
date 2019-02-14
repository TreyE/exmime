defmodule Exmime.Asn1.EnvelopedDataTest do
  use ExUnit.Case
  doctest Exmime.Asn1.EnvelopedData

  require Exmime.Records

  test "encode encrypted enveloped data using RSA and AES-CBC-256" do
    original_data = "A TEST MESSAGE 1\nA TEST MESSAGE 2\nA TEST MESSAGE 3"
    rem_bytes = rem(byte_size(original_data),16)
    padding_bytes = Exmime.Padding.Pkcs7Padding.provide_padding_of_length(16 - rem_bytes)
    data = original_data <> padding_bytes
    {cert_serial, rsa_pubkey_record} = Exmime.RsaTestHelpers.extract_cert_props()
    {aes_key, aes_iv} = Exmime.AesBlock.generate_AES_parameters(256)
    {:ok, ceaib} = Exmime.AesBlock.create_content_encryption_algorithm_identifier_binary(:exmime_constants.aes_256_cbc(),aes_iv)
    {eci_len, eci_bh} = Exmime.Asn1.EncryptedContentInfo.create_encrypted_content_info_binary_header(ceaib, byte_size(data))
    ri_info_binary = Exmime.Asn1.RecipientInfo.create_recipient_info_binary(rsa_pubkey_record, aes_key, cert_serial)
    {ri_binary_len, ri_binary} = Exmime.Asn1.RecipientInfo.create_recipient_info_sequence_binaries([ri_info_binary])
    encrypted_data = :crypto.block_encrypt(:aes_cbc256, aes_key, aes_iv, data)
    enveloped_data_header = Exmime.Asn1.EnvelopedData.create_enveloped_data_header_binary_as_content_info(
      ri_binary,
      ri_binary_len,
      eci_bh,
      eci_len
    )
    der_data = enveloped_data_header <> encrypted_data
    {:ok, out_f} = :file.open("ed_stream_aes_test_file_scratch.pkcs7", [:binary, :write])
    psw  = Exmime.PemStreamWriter.new_from_io(out_f, "PKCS7")
    psw
      |> Exmime.PemStreamWriter.initialize()
      |> Exmime.PemStreamWriter.write(der_data)
      |> Exmime.PemStreamWriter.finish()
    :file.close(out_f)
    {:ok, f} = :file.open("ed_stream_aes_test_file_scratch.pkcs7", [:binary, :read])
    new_stream = Exmime.PemStreamReader.new_from_io(f)
    f_stream = Exmime.PemStreamReader.wrap_as_file(new_stream)
    p_key = Exmime.RsaTestHelpers.read_private_key()
    ci = Exmime.Asn1.ContentInfo.decode_stream(f_stream, 0, new_stream.octet_length)
    decoded_stream = Exmime.decrypt_stream(p_key, ci)
    decoded_data = Enum.reduce(decoded_stream, <<>>, fn(e, acc) -> acc <> e end)
    ^original_data = decoded_data
    File.rm!("ed_stream_aes_test_file_scratch.pkcs7")
  end
end
