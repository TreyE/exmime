defmodule Exmime.Asn1.StreamingBerDecoder do
  def decode_stream(f, pos, max_pos) do
    with  <<d::binary>> <- IO.binread(f, 1),
          {tag_head, new_f} = match_tag_byte(d, f),
          <<l_byte::binary>> <- IO.binread(f, 1),
          {length, l_f} <- match_element_length(l_byte, new_f) do
      {decode_type, type_s} = type_specifier(tag_head)
      case decode_type do
        :object_identifier ->
          with(<<read::binary>> <- IO.binread(l_f, length)) do
            {{:object_identifier, decode_object_id(read)}, f}
          end
        :primitive ->
          with(<<read::binary>> <- IO.binread(l_f, length)) do
            {parse_primitive({type_s, length, read}), l_f}
          end
        :sequence ->
          with {:ok, n_pos} <- :file.position(l_f, :cur),
               {:ok, seq, seq_f} <- decode_sequence(f, n_pos, n_pos + length - 1, []) do
            {seq, seq_f}
          end
        :set ->
            with {:ok, n_pos} <- :file.position(l_f, :cur),
                 {:ok, seq, seq_f} <- decode_sequence(f, n_pos, n_pos + length - 1, []) do
              {MapSet.new(seq), seq_f}
            end
        _ ->
          with {:ok, n_pos} <- :file.position(l_f, :cur),
               {:ok, _} <- :file.position(l_f, n_pos + length) do
            {{{decode_type, type_s}, n_pos, length}, l_f}
          end
      end
    end
  end

  def split_sequence_elements(f, pos, max_pos, items) when pos > max_pos do
    {:ok, Enum.reverse(items), f}
  end

  def split_sequence_elements(f, pos, max_pos, items) do
    with {:ok, sequence_item_start_index} <- :file.position(f, :cur),
          <<d::binary>> <- IO.binread(f, 1),
          {tag_head, new_f} = match_tag_byte(d, f),
          <<l_byte::binary>> <- IO.binread(f, 1),
          {length, l_f} <- match_element_length(l_byte, new_f),
          {:ok, data_start_pos} <- :file.position(l_f, :cur),
          {:ok, n_pos} <- :file.position(l_f, data_start_pos + length),
          type_s <- type_specifier(tag_head) do
      split_sequence_elements(l_f, n_pos, max_pos, [{type_s, sequence_item_start_index, data_start_pos - pos + length, data_start_pos, length}|items])
    end
  end

  @spec offset_movement(number(), number()) :: number()
  def offset_movement(start, length) do
    offset_loc = start + length - 1
    case (length < 1) do
      false -> offset_loc
      _ -> start
    end
  end

  def decode_sequence(f, pos, max_pos, items) when pos > max_pos do
    {:ok, Enum.reverse(items), f}
  end

  def decode_sequence(f, pos, max_pos, items) do
    {new_val, new_f} = decode_stream(f, pos, max_pos)
    with({:ok, new_pos} <- :file.position(new_f, :cur)) do
      decode_sequence(new_f, new_pos, max_pos, [new_val|items])
    end
  end

  def decode_object_id(<<>>) do
    {}
  end

  def decode_object_id(<<first_parts::size(8),rest::binary>>) do
    object_id_large_bits = object_id_next_sets([], [], rest)
    List.to_tuple([div(first_parts, 40),Integer.mod(first_parts,40)|object_id_large_bits])
  end

  defp object_id_next_sets([], list, <<>>) do
    Enum.reverse(list)
  end

  defp object_id_next_sets(current, list, <<>>) do
    {_, multiplied_parts_result} = Enum.reduce(
      current,
      {0, 0},
      fn(b, {place, total}) ->
        {place + 1, total + (b * trunc(:math.pow(128, place)))}
      end
    )
    Enum.reverse([multiplied_parts_result|list])
  end

  defp object_id_next_sets([],list, <<0::size(1), oid_component::size(7), rest::binary>>) do
    object_id_next_sets([], [oid_component|list],rest)
  end

  defp object_id_next_sets(current,list, <<0::size(1), oid_component::size(7), rest::binary>>) do
    {_, multiplied_parts_result} = Enum.reduce(
          [oid_component | current],
          {0, 0},
          fn(b, {place, total}) ->
            {place + 1, total + (b * trunc(:math.pow(128, place)))}
          end
    )
    object_id_next_sets([], [multiplied_parts_result|list],rest)
  end

  defp object_id_next_sets(current, list, <<1::size(1), oid_component::size(7), rest::binary>>) do
    object_id_next_sets([oid_component|current],list,rest)
  end

  def match_tag_byte(<<class::size(2), constructed::size(1), 31::size(5)>>, f) do
    with( <<t_byte::binary>> <- IO.binread(f,1) ) do
      {tag, remaining} = read_other_tag_bytes([], t_byte, f)
      {{class, (constructed == 1), tag}, remaining}
    end
  end

  def match_tag_byte(<<class::size(2), constructed::size(1), low_tag::size(5)>>, f) do
    {{class, (constructed == 1), low_tag}, f}
  end

  defp read_other_tag_bytes(t_bytes, <<0::size(1), t_val::size(7)>>, f) do
    {Enum.reverse([t_bytes | t_val]), f}
  end

  defp read_other_tag_bytes(t_bytes, <<1::size(1), t_val::size(7)>>, f) do
    with( <<t_byte::binary>> <- IO.binread(f,1) ) do
      read_other_tag_bytes([t_bytes | t_val], t_byte, f)
    end
  end

  def match_element_length(<<0::size(1), len::size(7)>>, f) do
    {len, f}
  end

  def match_element_length(<<1::size(1), octet_count::size(7)>>, f) do
    with(<<len_bytes::binary>> <- IO.binread(f, octet_count)) do
      {read_rest_length_bytes(0, octet_count, len_bytes), f}
    end
  end

  defp read_rest_length_bytes(current_len, 0, _) do
    current_len
  end

  defp read_rest_length_bytes(current_len, i, <<count::size(8), rest::binary>>) do
    read_rest_length_bytes(current_len + (count * trunc(:math.pow(256, (i - 1)))), i - 1, rest)
  end

  defp parse_primitive({{_, _, :integer}, len, bytes}) do
    read_integer_value(bytes, 0, len - 1)
  end

  defp parse_primitive(a) do
    a
  end

  defp read_integer_value(<<>>, total, _) do
    total
  end

  defp read_integer_value(<<b_val::size(8), bytes::binary>>, total, base) do
    read_integer_value(bytes, total + (b_val * trunc(:math.pow(256,base))), base - 1)
  end

  @type_tags %{
    0 => :end_of_content,
    1 => :boolean,
    2 => :integer,
    3 => :bit_string,
    4 => :octet_string,
    5 => :null,
    6 => :object_identifier,
    7 => :object_descriptor,
    8 => :external,
    9 => :real,
    10 => :enumerated,
    12 => :utf8_string,
    13 => :relative_oid,
    16 => :sequence,
    17 => :set,
    18 => :numeric_string,
    19 => :printable_string,
    20 => :t61_string,
    22 => :ia5_string,
    23 => :utc_time
  }

  @prim_types %{
    0 => :end_of_content,
    1 => :boolean,
    2 => :integer,
    3 => :bit_string,
    4 => :octet_string,
    5 => :null,
    6 => :object_identifier,
    7 => :object_descriptor,
    8 => :external,
    9 => :real,
    10 => :enumerated,
    12 => :utf8_string,
    13 => :relative_oid,
    18 => :numeric_string,
    19 => :printable_string,
    20 => :t61_string,
    22 => :ia5_string,
    23 => :utc_time
  }

  defp type_specifier({0, constructed, 6}) do
    {:object_identifier, {0, constructed, :object_identifier}}
  end

  defp type_specifier({0, constructed, type}) when is_integer(type) and type < 31 do
    case Map.has_key?(@prim_types, type) do
      true -> {:primitive, {0, constructed, @type_tags[type]}}
      _ ->
          case type do
            16 -> {:sequence, {0, constructed, @type_tags[type]}}
            17 -> {:set, {0, constructed, @type_tags[type]}}
            _ -> {:other, {0, constructed, @type_tags[type]}}
          end
    end
  end

  defp type_specifier({0, constructed, type}) do
    {:tagged_type, {0, constructed, type}}
  end

  defp type_specifier({1, constructed, type}) do
    {:application, {1, constructed, type}}
  end

  defp type_specifier({2, constructed, type}) do
    {:context_specific, {2, constructed, type}}
  end

  defp type_specifier({3, constructed, type}) do
    {:private, {3, constructed, type}}
  end
end
