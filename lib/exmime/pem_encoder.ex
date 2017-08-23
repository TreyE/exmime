defmodule Exmime.PemEncoder do
  def encode_content_info(content_info_structure) do
    :public_key.pem_entry_encode(:ContentInfo, content_info_structure)
  end
end
