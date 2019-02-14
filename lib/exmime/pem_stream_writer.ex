defmodule Exmime.PemStreamWriter do
  defstruct [buffer: <<>>, io: nil, kind: <<>>, blocks_written_this_line: 0]

  def new_from_io(f, write_kind) do
    %__MODULE__{io: f, kind: write_kind}
  end

  def initialize(%__MODULE__{io: f, kind: k} = psw) do
    IO.binwrite(f, ["-----BEGIN ", k, "-----\n"])
    psw
  end

  def write(%__MODULE__{buffer: b} = psw, data) do
    case can_consume_buffer?(b, data) do
      false -> %__MODULE__{psw | buffer: (b <> data)}
      _ -> write_buffer(psw, data)
    end
  end

  def finish(%__MODULE__{io: f, kind: k, buffer: b}) do
    IO.binwrite(f, [Base.encode64(b), "\n-----END ", k, "-----\n"])
  end

  defp can_consume_buffer?(buff, data) do
    (byte_size(buff) + byte_size(data)) >= 3
  end

  defp write_buffer(%__MODULE__{io: f, buffer: b, blocks_written_this_line: bw} = psw, data) do
    work_binary = b <> data
    wb_size = byte_size(work_binary)
    available_chunks = div(wb_size, 3)
    remaining_chunks = rem(wb_size, 3)
    writable_bin = :binary.part(work_binary,0, available_chunks * 3)
    remaining_chunks = :binary.part(work_binary, available_chunks * 3, remaining_chunks)
    wtl_left = write_binaries(f, bw, writable_bin)
    %__MODULE__{psw | buffer: remaining_chunks, blocks_written_this_line: wtl_left}
  end

  defp write_binaries(_, written_this_line, <<>>) do
    written_this_line
  end

  defp write_binaries(f, 15, <<bin::binary-size(3),rest::binary>>) do
    IO.binwrite(f, [Base.encode64(bin), "\n"])
    write_binaries(f, 0, rest)
  end

  defp write_binaries(f, written_this_line, <<bin::binary-size(3),rest::binary>>) do
    IO.binwrite(f, Base.encode64(bin))
    write_binaries(f, written_this_line + 1, rest)
  end
end
