defmodule Exmime.RecordHelper do

  defmacro create_records do
    records = Record.extract_all(from_lib: "public_key/asn1/OTP-PUB-KEY.hrl")
    Enum.map(records, fn(rec) ->
      {name, fields} = rec
      #r_name = String.to_atom(Macro.underscore(Atom.to_string(name)))
      r_name = name
    quote do
      Record.defrecord unquote(r_name), unquote(name), unquote(fields)
    end
    end)
  end
end
