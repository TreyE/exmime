defmodule Exmime.PemStreamWriter do
  @eol_char <<"\n">>

  defstruct [
    buffer: <<>>,
    io: nil,
    kind: <<>>,
    blocks_written_this_line: 0,
    current_eof: 0,
    current_f_position: 0,
    current_data_position: 0,
    current_data_eof: 0,
    data_start_offset: nil
  ]

  def new_from_io(f, write_kind) do
    %__MODULE__{io: f, kind: write_kind}
  end

  def initialize(%__MODULE__{io: f, kind: k} = psw) do
    IO.binwrite(f, ["-----BEGIN ", k, "-----", @eol_char])
    with({:ok, pos} <- :file.position(f, :cur)) do
      %__MODULE__{psw | data_start_offset: pos}
    end
  end

  def write(psw, <<>>) do
    psw
  end

  def write(%__MODULE__{buffer: b, current_data_position: cdp, current_data_eof: cdeof} = psw, data) when cdp == cdeof do
    case can_consume_buffer?(b, data) do
      false -> %__MODULE__{psw | buffer: (b <> data)}
      _ -> write_buffer(psw, data)
    end
  end

  def write(%__MODULE__{current_data_position: cdp} = psw, data) do
    case ((cdp + byte_size(data)) > psw.current_data_eof) do
      false -> write_tritets_upto_end(psw, data)
      _ ->
        overwrite_data_size = (psw.current_data_eof - cdp)
        overwrite_data = :binary.part(data, 0, overwrite_data_size)
        leftover_data = :binary.part(data, overwrite_data_size, byte_size(data) - overwrite_data_size)
        new_psw = write_tritets_upto_end(psw, overwrite_data)
        write(new_psw, leftover_data)
    end
  end

  defp write_tritets_upto_end(%__MODULE__{current_data_position: cdp} = psw, data) do
    {start_tritet, part_of_start_tritet} = Exmime.B64FileStreaming.map_tritet_for_offset(cdp)
    {end_tritet, part_of_end_tritet} = Exmime.B64FileStreaming.map_tritet_for_offset(cdp + byte_size(data) - 1)
    case start_tritet do
      ^end_tritet ->
        rewrite_tritet(psw, start_tritet, part_of_start_tritet, data)
      _ -> split_multi_tritet_write(psw, {start_tritet, part_of_start_tritet}, {end_tritet, part_of_end_tritet}, data)
    end
  end

  defp split_multi_tritet_write(psw, {start_tritet, part_of_start_tritet}, {end_tritet, part_of_end_tritet}, data) do
     case ((end_tritet - start_tritet) > 1) do
       false ->
         first_bytes = :binary.part(data, 0, 3 - part_of_start_tritet)
         last_bytes = :binary.part(data, 3 - part_of_start_tritet, byte_size(data) - (3 - part_of_start_tritet))
         rewrite_tritet(psw, start_tritet, part_of_start_tritet, first_bytes)
         rewrite_last_tritet(psw, end_tritet, part_of_end_tritet, last_bytes)
       _ ->
        first_bytes = :binary.part(data, 0, 3 - part_of_start_tritet)
        last_bytes = :binary.part(data, byte_size(data) - part_of_end_tritet - 1, part_of_end_tritet + 1)
        middle_bytes = :binary.part(data, 3 - part_of_start_tritet, byte_size(data) - (part_of_end_tritet + 1) - ( 3 - part_of_start_tritet))
        rewrite_tritet(psw, start_tritet, part_of_start_tritet, first_bytes)
        direct_tritet_overwrite(psw, start_tritet + 1, middle_bytes)
        rewrite_last_tritet(psw, end_tritet, part_of_end_tritet, last_bytes)
     end
  end

  defp direct_tritet_overwrite(psw, tritet_index, <<>>) do
    with({:ok, pos} <- :file.position(psw.io, :cur)) do
      check_correct_position(%__MODULE__{psw | current_data_position: (tritet_index * 3), current_f_position: pos})
    end
  end

  defp direct_tritet_overwrite(%__MODULE__{} = psw, tritet_index, <<data::binary-size(3), rest::binary>>) do
    tritet_pos = Exmime.B64FileStreaming.map_io_loc_for_tritet(tritet_index, psw.data_start_offset, 63,1)
    :file.position(psw.io, tritet_pos)
    IO.binwrite(psw.io, Base.encode64(data))
    case (rem(tritet_index, 48) == 47) do
      false -> :ok
      _ -> IO.binwrite(psw.io, @eol_char)
    end
    direct_tritet_overwrite(psw, tritet_index + 1, rest)
  end

  defp rewrite_last_tritet(%__MODULE__{} = psw, tritet_index, _, <<data::binary-size(3)>>) do
    direct_tritet_overwrite(psw, tritet_index, data)
  end

  defp rewrite_last_tritet(%__MODULE__{io: f} = psw, tritet_index, tritet_rem, data) do
    tritet_pos = Exmime.B64FileStreaming.map_io_loc_for_tritet(tritet_index, psw.data_start_offset, 63, 1)
    :file.position(f, tritet_pos)
    with <<existing_tritet::binary>> <- IO.binread(f, 4),
         {:ok, existing_bin} <- Base.decode64(existing_tritet) do
         existing_second_part = :binary.part(existing_bin, tritet_rem + 1, 3 - tritet_rem - 1)
         writable_data = data <> existing_second_part
         with({:ok, _} <- :file.position(psw.io, tritet_pos)) do
           IO.binwrite(psw.io, Base.encode64(writable_data))
           case (rem(tritet_index, 48) == 47) do
             false -> :ok
             _ -> IO.binwrite(psw.io, @eol_char)
           end
           with({:ok, pos} <- :file.position(psw.io, :cur)) do
             check_correct_position(%__MODULE__{psw | current_data_position: ((tritet_index * 3) + byte_size(data)), current_f_position: pos})
           end
         end
    end
  end

  defp rewrite_tritet(%__MODULE__{io: f} = psw, tritet_index, tritet_rem, data) do
    tritet_pos = Exmime.B64FileStreaming.map_io_loc_for_tritet(tritet_index, psw.data_start_offset, 63, 1)
    :file.position(f, tritet_pos)
    with <<existing_tritet::binary>> <- IO.binread(f, 4),
         {:ok, existing_bin} <- Base.decode64(existing_tritet) do
         existing_first_part = :binary.part(existing_bin, 0, tritet_rem)
         existing_second_part = :binary.part(existing_bin, tritet_rem, 3 - (tritet_rem + byte_size(data)))
         writable_data = existing_first_part <> data <> existing_second_part
         with({:ok, _} <- :file.position(psw.io, tritet_pos)) do
           IO.binwrite(psw.io, Base.encode64(writable_data))
           case (rem(tritet_index, 48) == 47) do
             false -> :ok
             _ -> IO.binwrite(psw.io, @eol_char)
           end
           with({:ok, pos} <- :file.position(psw.io, :cur)) do
             check_correct_position(%__MODULE__{psw | current_data_position: ((tritet_index * 3) + byte_size(data)), current_f_position: pos})
           end
         end
    end
  end

  def check_correct_position(psw) do
    new_data_eof = case (psw.current_data_position > psw.current_data_eof) do
      false -> psw.current_data_eof
      _ -> psw.current_data_position
    end
    updated_eof = case (psw.current_f_position > psw.current_eof) do
      false -> psw.current_eof
      _ -> psw.current_f_position
    end
    %__MODULE__{
      psw |
        current_data_eof: new_data_eof,
        current_eof: updated_eof
      }
  end

  def position(%__MODULE__{current_data_position: cdp} = psw, :cur) do
    {:ok, psw, cdp}
  end

  def position(%__MODULE__{} = psw, :bof) do
    {:ok, %__MODULE__{psw | current_data_position: 0}, 0}
  end

  def position(%__MODULE__{} = psw, :eof) do
    {:ok, %__MODULE__{psw | current_data_position: psw.current_data_eof}, 0}
  end

  def position(%__MODULE__{} = psw, idx) when is_number(idx) do
    {:ok, %__MODULE__{psw | current_data_position: idx}, idx}
  end

  def finish(%__MODULE__{io: f, kind: k, buffer: <<>>, blocks_written_this_line: 0}) do
    :file.position(f, :eof)
    IO.binwrite(f, ["-----END ", k, "-----\n"])
  end

  def finish(%__MODULE__{io: f, kind: k, buffer: <<>>}) do
    :file.position(f, :eof)
    IO.binwrite(f, [@eol_char, "-----END ", k, "-----", @eol_char])
  end

  def finish(%__MODULE__{io: f, kind: k, buffer: b}) do
    :file.position(f, :eof)
    IO.binwrite(f, [Base.encode64(b), @eol_char, "-----END ", k, "-----", @eol_char])
  end

  defp can_consume_buffer?(buff, data) do
    (byte_size(buff) + byte_size(data)) >= 3
  end

  defp write_buffer(%__MODULE__{data_start_offset: dso, buffer: b, blocks_written_this_line: bw, current_eof: ceof} = psw, data) do
    work_binary = b <> data
    wb_size = byte_size(work_binary)
    available_chunks = div(wb_size, 3)
    remaining_chunks = rem(wb_size, 3)
    writable_bin = :binary.part(work_binary,0, available_chunks * 3)
    remaining_chunks = :binary.part(work_binary, available_chunks * 3, remaining_chunks)
    {new_loc, wtl_left} = write_binaries(psw, bw, writable_bin)
    updated_ceof = case (new_loc > ceof) do
                     false -> ceof
                     _ -> new_loc
                   end
    cdp = Exmime.B64FileStreaming.bytestream_location_from_file_position(new_loc, dso, 63, 1, byte_size(remaining_chunks))
    %__MODULE__{
      psw |
        current_data_position: cdp,
        current_eof: updated_ceof,
        current_f_position: new_loc,
        buffer: remaining_chunks,
        blocks_written_this_line: wtl_left,
        current_data_eof: cdp
      }
  end

  defp write_binaries(%__MODULE__{io: f}, written_this_line, <<>>) do
    with ({:ok, new_loc} <- :file.position(f, :cur)) do
      {new_loc, written_this_line}
    end
  end

  defp write_binaries(%__MODULE__{io: f} = psw, 0, <<bin::binary-size(48),rest::binary>>) do
    IO.binwrite(f, [Base.encode64(bin), @eol_char])
    write_binaries(psw, 0, rest)
  end

  defp write_binaries(%__MODULE__{io: f} = psw, 15, <<bin::binary-size(3),rest::binary>>) do
    IO.binwrite(f, [Base.encode64(bin), @eol_char])
    write_binaries(psw, 0, rest)
  end

  defp write_binaries(%__MODULE__{io: f} = psw, written_this_line, <<bin::binary-size(3),rest::binary>>) do
    IO.binwrite(f, Base.encode64(bin))
    write_binaries(psw, written_this_line + 1, rest)
  end
end
