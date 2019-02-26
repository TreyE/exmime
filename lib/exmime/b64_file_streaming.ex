defmodule Exmime.B64FileStreaming do
  def map_offset(idx, skip_start, skip_size) do
    row_count = div(idx, skip_start)
    idx + (row_count * skip_size)
  end

  def map_tritet_for_offset(byte_idx) do
    {div(byte_idx,3), rem(byte_idx,3)}
  end

  def bytestream_location_from_file_position(file_position, data_start_offset, skip_start, skip_size, other_data_length) do
    raw_file_distance = file_position - data_start_offset
    raw_b64_bytes = raw_file_distance - (div(raw_file_distance, skip_start + skip_size) * skip_size)
    (div(raw_b64_bytes, 4) * 3) + other_data_length
  end

  def map_io_loc_for_tritet(tritet_index, data_start_offset, skip_start, skip_length) do
    map_offset((tritet_index * 4), skip_start, skip_length) + data_start_offset
  end
end
