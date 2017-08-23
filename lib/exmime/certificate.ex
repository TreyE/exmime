defmodule Exmime.Certificate do
  require Exmime.Records

  def extract_rsa_public_key(decoded_cert_pem) do
    extract_tbs_cert(decoded_cert_pem) |>
      extract_tbs_pubkey_info |>
        extract_rsa_keyinfo_pubkey
  end

  def extract_serial_number(decoded_cert_pem) do
    extract_tbs_cert(decoded_cert_pem) |>
      extract_tbs_serial_number
  end

  defp extract_tbs_cert(decoded_cert_pem) do
    Exmime.Records.'Certificate'(
      decoded_cert_pem,
      :tbsCertificate
    )
  end

  defp extract_tbs_serial_number(tbs_cert) do
    Exmime.Records.'TBSCertificate'(
      tbs_cert,
      :serialNumber
    )
  end

  defp extract_tbs_pubkey_info(tbs_cert) do
    Exmime.Records.'TBSCertificate'(
      tbs_cert,
      :subjectPublicKeyInfo
    )
  end

  defp extract_rsa_keyinfo_pubkey(s_pki) do
    pkey = Exmime.Records.'SubjectPublicKeyInfo'(
      s_pki,
      :subjectPublicKey
    )
    [m, e] = decode_public_key_asn1(pkey)
  end

  defp decode_public_key_asn1(<<48::size(8), rest::binary>>) do
    decode_asn1_sequence(rest)
  end

  defp decode_asn1_sequence(<<len::integer-size(8), rest::binary>>) do
    case len > 127 do
      true ->
        {len_val, remaining_data} = read_len_bytes(rest, len - 128)
        parse_sequence_items(len_val, remaining_data)
      _ -> parse_sequence_items(len, rest)
    end
  end

  defp decode_asn1_primitive(<<type::unsigned-integer-size(8), len::unsigned-integer-size(8), rest::binary>>) do
    case len > 127 do
      true ->
        {len_val, remaining_data} = read_len_bytes(rest, len - 128)
        parse_primitive(type, len_val, remaining_data)
      _ -> parse_primitive(type, len, rest)
    end
  end

  defp parse_primitive(2, length, data) do
    bit_count = length * 8
    <<value::signed-big-integer-size(bit_count), rest::binary>> = data
    {rest, value}
  end

  defp read_len_bytes(data, len_byte_count) do
    bit_count = len_byte_count * 8
    <<len_val::unsigned-big-integer-size(bit_count), rest::binary>> = data
    {len_val, rest}
  end

  defp parse_sequence_items(len, data) do
    <<sequence_binary::binary-size(len), _::binary>> = data
    read_sequence_items(sequence_binary, [])
  end

  defp read_sequence_items(<<>>, list) do
    Enum.reverse(list)
  end

  defp read_sequence_items(sequence_data, list) do
    {rest, item} = decode_asn1_primitive(sequence_data)
    read_sequence_items(rest, [item|list])
  end
end
