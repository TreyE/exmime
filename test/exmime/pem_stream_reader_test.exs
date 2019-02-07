defmodule Exmime.PemStreamReaderTest do
  use ExUnit.Case
  doctest Exmime.PemStreamReader

  test "read a simple pem" do
    {:ok, f} = :file.open("example.smime", [:binary, :read])
    new_stream = Exmime.PemStreamReader.new_from_io(f)
    f = Exmime.PemStreamReader.wrap_as_file(new_stream)
    IO.inspect(:file.position(f,:cur))
    IO.inspect(IO.binread(f, 3))
    IO.inspect(:file.position(f,:cur))
    IO.inspect(IO.binread(f, :all))
    IO.inspect(:file.position(f,:cur))
    File.close(f)
  end

  test "test offset function with a non-zero end of line" do
    0 = Exmime.PemStreamReader.map_pos(0, 63, 1)
    62 = Exmime.PemStreamReader.map_pos(62, 63, 1)
    64 = Exmime.PemStreamReader.map_pos(63, 63, 1)
    65 = Exmime.PemStreamReader.map_pos(63, 63, 2)
    68 = Exmime.PemStreamReader.map_pos(63, 63, 5)
    128 = Exmime.PemStreamReader.map_pos(126, 63, 1)
    136 = Exmime.PemStreamReader.map_pos(126, 63, 5)
    192 = Exmime.PemStreamReader.map_pos(189, 63, 1)
    195 = Exmime.PemStreamReader.map_pos(189, 63, 2)
  end

  test "test data length function with a non-zero end of line" do
    {:ok, 4} = Exmime.PemStreamReader.b64_data_length(0, 3, 60, 2)
    {:ok, 8} = Exmime.PemStreamReader.b64_data_length(0, 9, 4, 2)
    {:ok, 12} = Exmime.PemStreamReader.b64_data_length(0, 15, 4, 2)
    {:ok, 520} = Exmime.PemStreamReader.b64_data_length(22, 549, 64, 1)
    {:ok, 68} = Exmime.PemStreamReader.b64_data_length(0, 68, 64, 1)
    {:ok, 4} = Exmime.PemStreamReader.b64_data_length(1, 4, 61, 2)
    {:ok, 64} = Exmime.PemStreamReader.b64_data_length(1, 66, 61, 2)
    {:ok, 64} = Exmime.PemStreamReader.b64_data_length(1, 66, 62, 2)
  end
end
