defmodule Exmime.PemStreamReader do
  defstruct [
    io: nil,
    data_start: nil,
    data_end: nil,
    octet_length: nil,
    skip_size: nil,
    skip_start: nil,
    byte_pos: 0
  ]

  @base_64_alphabet [
   "A","B","C","D","E","F","G","H",
   "I","J","K","L","M","N","O","P",
   "Q","R","S","T","U","V","W","X",
   "Y", "Z",
   "a","b","c","d","e","f","g","h",
   "i","j","k","l","m","n","o","p",
   "q","r","s","t","u","v","w","x",
   "y", "z",
   "0", "1", "2", "3", "4", "5",
   "6", "7", "8", "9",
   "+", "/", "=", ".", "_", ",",
   ":", "~"
  ]

  def new_from_io(f) do
    with {:ok, new_f, data_start} <- find_start_of_pem_data_block(f),
        {:ok, end_f, data_end} <- find_end_of_pem_data_block(new_f),
        {:ok, lb_f, skip_found_at, skip_size} <- find_line_breaks(end_f, data_start, data_end),
        {:ok, total_b64_len} <- b64_data_length(data_start, data_end, skip_found_at - data_start, skip_size),
        {:ok, b64_bytes_difference} <- missing_final_byte_count(f, data_start, total_b64_len, skip_found_at - data_start, skip_size) do
    skip_start = case skip_size do
                   0 -> 0
                   _ -> skip_found_at - data_start
                 end
    octet_size = div((total_b64_len * 3), 4) - b64_bytes_difference
    %__MODULE__{
      data_start: data_start,
      data_end: data_end,
      skip_size: skip_size,
      skip_start: skip_start,
      io: lb_f,
      octet_length: octet_size,
      byte_pos: 0
    }
  end
  end

  def wrap_as_file(stream) do
    spawn(fn() -> loop(stream) end)
  end

  defp loop(stream) do
    receive do
      {:io_request, from, reply_ref, {:get_chars, :"", n}} ->
        handle_read_request(from, reply_ref, stream, n)
      {:file_request, from, reply_ref, {:position, p}} ->
        handle_position_request(from, reply_ref, stream,p)
      {:file_request, from, reply_ref, :close} ->
        send(from, {:file_reply,reply_ref, File.close(stream.io)})
      a ->
        IO.inspect(a)
        loop(stream)
    end
  end

  defp handle_read_request(from, reply_ref, stream, n) do
    case read(stream, n) do
      {:ok, new_s, data} ->
          send(from, {:io_reply,reply_ref, data})
          loop(new_s)
      :eof ->
        send(from, {:io_reply, reply_ref, :eof})
        loop(stream)
      a ->
        send(from, {:io_reply, reply_ref, {:error, a}})
        loop(stream)
    end
  end

  defp handle_position_request(from, reply_ref, stream, p) do
    case position(stream, p) do
      {:ok, new_s, new_p} ->
          send(from, {:file_reply,reply_ref, {:ok, new_p}})
          loop(new_s)
      a ->
        send(from, {:file_reply, reply_ref, {:error, a}})
        loop(stream)
    end
  end

  # We need to calculate the offset including our EOL chars.
  # Basically this is the same as a two dimentional array stored
  # in packed one-dimensional mapping.
  def map_pos(idx, skip_start, skip_size) do
    Exmime.B64FileStreaming.map_offset(idx, skip_start, skip_size)
  end
  def map_coords(idx, 0, _) do
    {idx, 0}
  end

  def map_coords(idx, skip_start, skip_size) do
    row_count = div(idx, skip_start)
    {idx + (row_count * skip_size), row_count}
  end

  def b64_data_length(data_start, data_end, skip_start, skip_size) do
    len = data_end - data_start + 1
    total_len = len - (div(len, skip_start + skip_size) * skip_size)
    case (rem(total_len,4)) do
      0 -> {:ok, total_len}
      a -> {:error, :padding_invalid, a}
    end
  end

  def map_tritet_for_byte(byte_idx) do
    Exmime.B64FileStreaming.map_tritet_for_offset(byte_idx)
  end

  def missing_final_byte_count(f, data_start, b64_len, skip_start, skip_size) do
    last_data_index = data_start + map_pos(b64_len - 2, skip_start, skip_size)
    :file.position(f, {:bof, last_data_index})
    with {:ok, subtracted_penultimate_byte} <- blank_b64_byte(IO.binread(f, 1)),
         {:ok, subtracted_last_byte} <- blank_b64_byte(IO.binread(f, 1)) do
      {:ok, subtracted_last_byte + subtracted_penultimate_byte}
    end
  end

  defp blank_b64_byte(<<"=">>), do: {:ok, 1}
  defp blank_b64_byte(<<_::binary>>), do: {:ok, 0}
  defp blank_b64_byte(a), do: a

  defp find_end_of_pem_data_block(f) do
    {:ok, c_pos} = :file.position(f, {:eof, -1})
    read_next_pem_footer_byte(:unstarted, f, c_pos)
  end

  defp find_start_of_pem_data_block(f) do
    {:ok, _} = :file.position(f, :bof)
    read_next_pem_header_byte(:unstarted, f)
  end

  defp read_next_pem_header_byte(:unstarted, f) do
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_header_byte(:in_header_start, f)
      _ -> read_next_pem_header_byte(:unstarted, f)
    end
  end

  defp read_next_pem_header_byte(:in_header_start, f) do
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_header_byte(:in_header_start, f)
      _ -> read_next_pem_header_byte(:in_header_label, f)
    end
  end

  defp read_next_pem_header_byte(:in_header_label, f) do
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_header_byte(:in_header_end, f)
      _ -> read_next_pem_header_byte(:in_header_label, f)
    end
  end

  defp read_next_pem_header_byte(:in_header_end, f) do
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_header_byte(:in_header_end, f)
      data ->
        case Enum.member?(@base_64_alphabet, data) do
          false ->
            read_next_pem_header_byte(:in_header_end, f)
          _ ->
            {:ok, new_pos} = :file.position(f, :cur)
            {:ok, f, new_pos - 1}
        end
    end
  end

  defp read_next_pem_footer_byte(:unstarted, f, c_pos) do
    {:ok, new_pos} = :file.position(f, c_pos)
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_footer_byte(:in_header_start, f, new_pos - 1)
      _ -> read_next_pem_footer_byte(:unstarted, f, new_pos - 1)
    end
  end

  defp read_next_pem_footer_byte(:in_header_start, f, c_pos) do
    {:ok, new_pos} = :file.position(f, c_pos)
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_footer_byte(:in_header_start, f, new_pos - 1)
      _ -> read_next_pem_footer_byte(:in_header_label, f, new_pos - 1)
    end
  end

  defp read_next_pem_footer_byte(:in_header_label, f, c_pos) do
    {:ok, new_pos} = :file.position(f, c_pos)
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_footer_byte(:in_header_end, f, new_pos - 1)
      _ -> read_next_pem_footer_byte(:in_header_label, f, new_pos - 1)
    end
  end

  defp read_next_pem_footer_byte(:in_header_end, f, c_pos) do
    {:ok, new_pos} = :file.position(f, c_pos)
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      <<"-">> -> read_next_pem_footer_byte(:in_header_end, f, new_pos - 1)
      data ->
        case Enum.member?(@base_64_alphabet, data) do
          false -> read_next_pem_footer_byte(:in_header_end, f, new_pos - 1)
          _ -> {:ok, f, c_pos}
        end
    end
  end

  defp find_line_breaks(f, pem_data_start, pem_data_end) do
    {:ok, new_pos} = :file.position(f, pem_data_start)
    seek_line_break(f,new_pos,pem_data_end)
  end

  defp seek_line_break(f, c_pos, pem_data_end) when c_pos >= pem_data_end do
    {:ok, f, 0, 0}
  end

  defp seek_line_break(f, c_pos, pem_data_end) do
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      data -> case Enum.member?(@base_64_alphabet, data) do
                false -> in_line_break(f, c_pos, c_pos + 1, pem_data_end,1)
                _ -> seek_line_break(f, c_pos + 1, pem_data_end)
              end
    end
  end

  defp in_line_break(f, _, c_pos, pem_data_end, _) when c_pos >= pem_data_end do
    {:ok, f, 0, 0}
  end

  defp in_line_break(f, start, c_pos, pem_data_end, lb_len) do
    case IO.binread(f, 1) do
      {:error, reason} -> {:error, f, reason}
      :eof -> {:error, f, :eof}
      data -> case Enum.member?(@base_64_alphabet, data) do
                false -> in_line_break(f, start, c_pos + 1, pem_data_end, lb_len + 1)
                _ -> {:ok, f, start, lb_len}
              end
    end
  end

  def position(_, index) when index < 0 do
    {:err, :badarg}
  end

  def position(%__MODULE__{} = stream, :eof) do
    {:ok, %__MODULE__{stream | byte_pos: :eof}, :eof}
  end

  def position(%__MODULE__{} = stream, :bof) do
    {:ok, %__MODULE__{stream | byte_pos: 0}, 0}
  end

  def position(%__MODULE__{byte_pos: bp} = stream, :cur) do
    {:ok, stream, bp}
  end

  def position(%__MODULE__{octet_length: ol} = stream, index) when index >= 0  and index == ol do
    {:ok, %__MODULE__{stream| byte_pos: :eof}, :eof}
  end

  def position(%__MODULE__{octet_length: ol}, index) when index >= 0  and index > ol do
    {:err, :badarg}
  end

  def position(%__MODULE__{octet_length: ol} = stream, index) when index >= 0  and index < ol do
    {:ok, %__MODULE__{stream | byte_pos: index}, index}
  end

  def read(%__MODULE__{byte_pos: :eof}, _) do
    :eof
  end

  def read(stream, read_size) do
    suggested_end = (stream.byte_pos + read_size - 1)
    {byte_end, new_pos} = case (suggested_end >= (stream.octet_length - 1)) do
                 false -> { suggested_end, suggested_end + 1 }
                 _ -> {stream.octet_length - 1, :eof}
               end
    {start_tritet, bin_offset} = map_tritet_for_byte(stream.byte_pos)
    {end_tritet, end_bin_offset} = map_tritet_for_byte(byte_end)
    slice_end = ((end_tritet - start_tritet) * 3) + end_bin_offset
    tritets = map_tritets(start_tritet, end_tritet, stream.skip_start, stream.skip_size)
    with(<<data::binary>> <- read_and_slice_tritets(stream.io, tritets, stream.data_start, bin_offset, slice_end - bin_offset + 1)) do
      {:ok, %__MODULE__{stream | byte_pos: new_pos},  data}
    end
  end

  def read_and_slice_tritets(io, tritets, data_start, start_tritet_offset, end_offset) do
    data = Enum.reduce(tritets, <<>>,fn({o, length}, acc) when is_integer(o) ->
      :file.position(io, o + data_start)
      with <<a::binary>> <- IO.binread(io, length),
           {:ok, data} <- Base.decode64(a) do
        acc <> data
      end
    end)
    case data do
      <<bins::binary>> -> :binary.part(bins, start_tritet_offset, end_offset)
      a -> a
    end
  end

  defp map_tritets(start_t, end_t, skip_start, skip_len) do
    Enum.map(Range.new(start_t, end_t), fn(r) ->
      map_coords(r * 4, skip_start, skip_len)
    end)
      |> Enum.chunk_by(fn({_, row}) ->
           row
         end)
      |> Enum.map(fn(group) ->
           {first_index, _} = Enum.at(group, 0)
           {first_index, Enum.count(group) * 4}
         end)
  end
end
