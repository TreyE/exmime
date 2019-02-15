defmodule Exmime.Asn1.EnvelopedDataTest do
  use ExUnit.Case
  doctest Exmime.Asn1.EnvelopedData

  require Exmime.Records

  test "encode encrypted enveloped data using RSA and AES-CBC-256" do
    original_data = "A TEST MESSAGE 1\nA TEST MESSAGE 2\nA TEST MESSAGE 3"
    {cert_serial, rsa_pubkey_record} = Exmime.RsaTestHelpers.extract_cert_props()
    {:ok, e_mod} = Exmime.EncryptionAlgorithms.block_encryption_module(:aes_cbc256)
    padding_bytes = e_mod.padding_data(byte_size(original_data))
    data = original_data <> padding_bytes
    aes_key = e_mod.generate_key()
    aes_iv = e_mod.generate_parameters()
    {:ok, ceaib} = e_mod.create_content_encryption_algorithm_identifier_binary(aes_iv)
    {eci_len, eci_bh} = Exmime.Asn1.EncryptedContentInfo.create_encrypted_content_info_binary_header(ceaib, byte_size(data))
    ri_info_binary = Exmime.Asn1.RecipientInfo.create_recipient_info_binary(rsa_pubkey_record, aes_key, cert_serial)
    {ri_binary_len, ri_binary} = Exmime.Asn1.RecipientInfo.create_recipient_info_sequence_binaries([ri_info_binary])
    encrypted_data = e_mod.block_encrypt(aes_key, aes_iv, data)
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
    message_recipient_decoding_instructions = %Exmime.MessageRecipients.DecodingInstructions{
      private_key: p_key,
      serial_number: cert_serial,
      issuer: {:rdnSequence, []}
    }
    {:ok, decoding_stream} = Exmime.Asn1.EnvelopedData.decrypt_stream(ci, message_recipient_decoding_instructions)
    decoded_data = Enum.reduce(decoding_stream, <<>>, fn(e, acc) -> acc <> e end)
    ^original_data = decoded_data
    File.rm!("ed_stream_aes_test_file_scratch.pkcs7")
  end
end
