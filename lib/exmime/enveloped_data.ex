defmodule Exmime.EnvelopedData do
  require Exmime.Records

  def content_info(recipientInfos, encryptedContentInfo) do
    Exmime.Records.'ContentInfo'(
      contentType: :exmime_constants.envelopedData(),
      content: enveloped_data(recipientInfos, encryptedContentInfo)
    )
  end

  def enveloped_data(recipientInfos, encryptedContentInfo) do
    Exmime.Records.'EnvelopedData'(
      version: :edVer0,
      recipientInfos: {:riSet, recipientInfos},
      encryptedContentInfo: encryptedContentInfo
    )
  end

  def decode_content_info_encrypted_content_info(content_info) do
    content = Exmime.Records.'ContentInfo'(content_info, :content)
    Exmime.Records.'EnvelopedData'(content, :encryptedContentInfo)
  end
end
