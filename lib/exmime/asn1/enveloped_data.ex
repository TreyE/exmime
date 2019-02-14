defmodule Exmime.Asn1.EnvelopedData do
  defstruct [:version, recipient_infos: [], encrypted_content_info: []]

  @spec decode_contextual_type(pid() | {:file_descriptor, atom(), any()}, any(), any()) :: any()
  def decode_contextual_type(f, start, len) do
    with {:ok, s_pos} <- :file.position(f, :cur),
        {:ok, _} = :file.position(f, start),
        <<d::binary>> <- IO.binread(f, 1),
        {_, new_f} = Exmime.Asn1.StreamingBerDecoder.match_tag_byte(d, f),
        <<l_byte::binary>> <- IO.binread(new_f, 1),
        {length, l_f} <- Exmime.Asn1.StreamingBerDecoder.match_element_length(l_byte, new_f),
        {:ok, n_pos} <- :file.position(l_f, :cur),
        {version, v_f} <- Exmime.Asn1.StreamingBerDecoder.decode_stream(l_f, n_pos, n_pos + length - 1),
        {:ok, item_pos} = :file.position(v_f, :cur),
        {:ok, [r_infos, encrypted_content_info], seq_f} <- Exmime.Asn1.StreamingBerDecoder.split_sequence_elements(l_f, item_pos, start + len - 1, []) do
        val = %__MODULE__{
          version: version,
          recipient_infos: decode_recipient_infos(r_infos, seq_f),
          encrypted_content_info: decode_encrypted_content_info(encrypted_content_info, f)
        }
        :file.position(seq_f, s_pos)
        val
    end
  end

  defp decode_recipient_infos({{:set,_}, _, _, start, len}, f) do
    decode_recipient_info_collection(f, start, len)
  end

  defp decode_recipient_infos({{:sequence,_}, _, _, start, len}, f) do
    decode_recipient_info_collection(f, start, len)
  end

  defp decode_recipient_info_collection(f, start, len) do
    with {:ok, s_pos} <- :file.position(f, :cur),
         {:ok, _} <- :file.position(f, start),
         {:ok, items, si_f} <- Exmime.Asn1.StreamingBerDecoder.split_sequence_elements(f, start, start + len - 1, []) do
      vals = Enum.map(items, fn({_, i_start, i_len, _, _}) ->
        with {:ok, _} <- :file.position(f, i_start),
             <<data::binary>> <- IO.binread(f, i_len) do
            Exmime.Asn1.RecipientInfo.decode_binary(data)
        end
      end)
      :file.position(si_f, s_pos)
      vals
    end
  end

  defp decode_encrypted_content_info({{:sequence, _}, _, _, start, len}, f) do
    Exmime.Asn1.EncryptedContentInfo.decode(f, start, len)
  end

  def create_enveloped_data_header_binary_as_content_info(recipient_info_sequence_binary, ri_binary_len, encrypted_content_info_binary_header, encrypted_content_info_binary_header_len) do
    total_len_of_en_data_parts = 3 + ri_binary_len + encrypted_content_info_binary_header_len
    en_data_part_bytes = <<2::integer-size(8),1::integer-size(8),0::integer-size(8)>> <> recipient_info_sequence_binary <> encrypted_content_info_binary_header
    {seq_len, seq_bytes} = Exmime.Asn1.StreamingBerEncoder.wrap_item(<<16::integer-size(8)>>, en_data_part_bytes, total_len_of_en_data_parts)
    {context_seq_len, context_seq_bytes} = Exmime.Asn1.StreamingBerEncoder.wrap_item(<<160::integer-size(8)>>,seq_bytes, seq_len)
    encoded_object_id = Exmime.Asn1.StreamingBerEncoder.encode_object_id(:exmime_constants.envelopedData())
    ci_body_bytes = encoded_object_id <> context_seq_bytes
    ci_body_length = byte_size(encoded_object_id) + context_seq_len
    {_, full_content_info} = Exmime.Asn1.StreamingBerEncoder.wrap_item(<<48::integer-size(8)>>, ci_body_bytes, ci_body_length)
    full_content_info
  end

end
