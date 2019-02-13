defmodule Exmime.Asn1.StreamingBerDecoderTest do
  use ExUnit.Case
  doctest Exmime.Asn1.StreamingBerDecoder

  test "object decode" do
    {:ok, f} = :file.open("example.smime", [:binary, :read])
    new_stream = Exmime.PemStreamReader.new_from_io(f)
    f_stream = Exmime.PemStreamReader.wrap_as_file(new_stream)
    IO.inspect Exmime.Asn1.StreamingBerDecoder.decode_stream(f_stream, 0, new_stream.octet_length)
  end
end
