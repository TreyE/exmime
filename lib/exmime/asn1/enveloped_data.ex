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
end
