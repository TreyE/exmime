defmodule Exmime.Asn1.EncryptedContentInfo do
  defstruct [content_type: nil, content_encryption_algorithm: nil, encrypted_content: nil]

  def decode(f, start, len) do
    with {:ok, s_pos} <- :file.position(f, :cur),
         {:ok, _} <- :file.position(f, start),
         {c_type, ct_f} <- Exmime.Asn1.StreamingBerDecoder.decode_stream(f, start, start + len - 1),
         {:ok, pos} <- :file.position(ct_f, :cur),
         {:ok, [ceai,ec], seq_f} <- Exmime.Asn1.StreamingBerDecoder.split_sequence_elements(f, pos, start + len - 1, []) do
      :file.position(seq_f, s_pos)
      %__MODULE__{
        content_type: c_type,
        content_encryption_algorithm: decode_content_encryption_algorithm_identifier(ceai, f),
        encrypted_content: decode_encrypted_content(ec, f)
      }
    end
  end

  defp decode_content_encryption_algorithm_identifier({_, s_start, s_len, _, _}, f) do
    with {:ok, _} <- :file.position(f, s_start),
         <<data::binary>> <- IO.binread(f, s_len),
         {:ok, ceai} <- :'OTP-PUB-KEY'.decode(:'ContentEncryptionAlgorithmIdentifier', data) do
      ceai
    end
  end

  defp decode_encrypted_content({_, _, _, start, len}, f) do
    {:file_stream, f, start, len}
  end

end
