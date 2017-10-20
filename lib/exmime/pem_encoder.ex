defmodule Exmime.PemEncoder do
  @spec encode_content_info(tuple) :: :public_key.pem_entry
  def encode_content_info(content_info_structure) when is_tuple(content_info_structure) do
    :public_key.pem_entry_encode(:ContentInfo, content_info_structure)
  end
end
