defmodule Exmime.Padding.Pkcs7ReadStream do
  # Read from an IO and add padding
  @spec io_window_add_padding_stream(integer(), integer(), integer(), any()) ::
          ({:cont, any()} | {:halt, any()} | {:suspend, any()}, any() -> any())
  def io_window_add_padding_stream(block_byte_size, data_start, data_stop, io) when (data_stop >= data_start) do
    remaining = (data_start - data_stop + 1)
    Stream.resource(
      fn () -> {:cont, io, remaining} end,
      fn ({state, f, left}) -> read_current_add_padding_value(state, block_byte_size, left, f) end,
      fn ({f, status}) -> {f, status} end
    )
  end

  defp read_current_add_padding_value(:pad_block_size, block_byte_size, 0, io) do
    data = provide_padding_of_length(block_byte_size)
    {[data], {:done, io, 0}}
  end

  defp read_current_add_padding_value(_, _, 0, io) do
    {:halt, {io, 0}}
  end

  defp read_current_add_padding_value(:cont, block_byte_size, remaining, io) when (remaining == block_byte_size) do
    case IO.binread(io, block_byte_size) do
      :eof -> {:halt, {io, {:error, :eof}}}
      {:error, reason} -> {:halt, {io, {:error, reason}}}
      <<data::binary-size(block_byte_size)>> -> {[data], {:pad_block_size, io, 0}}
    end
  end

  defp read_current_add_padding_value(:cont, block_byte_size, remaining, io) when (remaining < block_byte_size) and (remaining > 0) do
    case IO.binread(io, remaining) do
      :eof -> {:halt, {io, {:error, :eof}}}
      {:error, reason} -> {:halt, {io, {:error, reason}}}
      <<data::binary-size(block_byte_size)>> -> {[data <> provide_padding_of_length(block_byte_size - remaining)], {:done, io, 0}}
    end
  end

  defp read_current_add_padding_value(:cont, block_byte_size, remaining, io) when (remaining > block_byte_size) do
    case IO.binread(io, block_byte_size) do
      :eof -> {:halt, {io, {:error, :eof}}}
      {:error, reason} -> {:halt, {io, {:error, reason}}}
      <<data::binary-size(block_byte_size)>> -> {[data], {:cont, io, remaining - block_byte_size}}
    end
  end

  defp provide_padding_of_length(len) when (len > 0) and (len <= 255) do
    :binary.copy(:binary.encode_unsigned(len), len)
  end
end
