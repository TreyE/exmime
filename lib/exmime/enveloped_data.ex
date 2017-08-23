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
end
