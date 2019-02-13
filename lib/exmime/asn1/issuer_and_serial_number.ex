defmodule Exmime.Asn1.IssuerAndSerialNumber do
  defstruct [
    issuer: nil,
    serial_number: nil
  ]

  require Exmime.Records

  def decode_record_parts(isn) do
    issuer = Exmime.Records.'IssuerAndSerialNumber'(isn, :issuer)
    sn = Exmime.Records.'IssuerAndSerialNumber'(isn, :serialNumber)
    %__MODULE__{
      issuer: issuer,
      serial_number: sn
    }
  end
end
