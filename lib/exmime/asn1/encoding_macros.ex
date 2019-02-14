defmodule Exmime.Asn1.EncodingMacros do
  defmacro define_length_encoding_functions() do
    Enum.map(Range.new(2,64), fn(radix) ->
      val = trunc(:math.pow(256,radix))
      oct_len_val = radix + 128
      quote do
        def encode_length_value(a) when a < unquote(val) do
          asn1_len_bytes_for(unquote(radix - 1), a, <<unquote(oct_len_val)::integer-size(8)>>)
        end
      end
    end)
  end
end
