defmodule Exmime.Asn1.ContentInfo do
  @enveloped_data_oid {1, 2, 840, 113549, 1, 7, 3}

  def decode_stream(f, pos, max_pos) do
    with  {:ok, o_pos} <- :file.position(f, :cur),
          {:ok, _} <- :file.position(f, pos),
          <<d::binary>> <- IO.binread(f, 1),
          {_, new_f} = Exmime.Asn1.StreamingBerDecoder.match_tag_byte(d, f),
          <<l_byte::binary>> <- IO.binread(f, 1),
          {_, l_f} <- Exmime.Asn1.StreamingBerDecoder.match_element_length(l_byte, new_f),
          {:ok, n_pos} <-  :file.position(l_f, :cur),
          {oid, oid_f} <- Exmime.Asn1.StreamingBerDecoder.decode_stream(l_f, n_pos, max_pos),
          {:ok, s_pos} <- :file.position(oid_f, :cur),
          {:ok, items, seq_f} = Exmime.Asn1.StreamingBerDecoder.split_sequence_elements(oid_f, s_pos, max_pos, []),
          {res, res_f} <- decode_context_type(oid,items, seq_f),
          {:ok, _} <- :file.position(res_f, o_pos) do
          res
    end
  end

  defp decode_context_type({:object_identifier, @enveloped_data_oid}, [{{:context_specific, {2, true, 0}}, _, _, start, len}], f) do
    Exmime.Asn1.EnvelopedData.decode_contextual_type(f, start, len)
  end

  defp decode_context_type(_,data, f) do
    {{:error, "unknown content info identifier", data}, f}
  end
end
