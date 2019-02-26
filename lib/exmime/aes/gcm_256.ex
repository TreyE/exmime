defmodule Exmime.Aes.Gcm256 do
  defmodule GcmState256 do
    defstruct [
      :key,
      :master_key,
      :aad,
      :plaintext_size,
      :current_ivec,
      :ghash_state,
      :stream_state,
      :eky0
    ]

    def new(session_key, aad, ctext_size, ivec) do
      masterkey = :crypto.block_encrypt(:aes_ecb, session_key, <<0::unsigned-integer-size(128)>>)
      mk = :crypto.bytes_to_integer(masterkey)
      # First GCM IVec
      iv0 = ivec <> <<1::unsigned-integer-big-size(32)>>
      # Initialize keys and crypto state
      state0 = :crypto.stream_init(:aes_ctr, session_key, iv0)
      {state1, eKY0xor} = :crypto.stream_encrypt(state0, iv0)
      # Last value to use for data tag xor
      eKY0 = :crypto.exor(eKY0xor, iv0)
      ghash_init = init_ghash_state(aad, ctext_size, mk)
      %__MODULE__{
        key: session_key,
        master_key: mk,
        aad: aad,
        ghash_state: ghash_init,
        current_ivec: iv0,
        stream_state: state1,
        eky0: eKY0
      }
    end

    def update(gs, new_stream_state, new_ivec, new_ghash) do
      {aad_size, c_text_bits_size, _} = gs.ghash_state
      %__MODULE__{
        gs |
          stream_state: new_stream_state,
          current_ivec: new_ivec,
          ghash_state: {aad_size, c_text_bits_size, new_ghash}
      }
    end

    defp init_ghash_state(aad, c_text_size, m_key) do
      aad_size = byte_size(aad) * 8
      c_text_bits_size = c_text_size * 8
      bghash = :exmime_ghash.gcm_ghash_multiply(:crypto.exor(<<0::unsigned-big-integer-size(128)>>, :exmime_ghash.gcm_pad(aad)), m_key)
      {aad_size, c_text_bits_size, bghash}
    end
  end

  def padding_data() do
    <<>>
  end

  def generate_key() do
    :crypto.strong_rand_bytes(32)
  end

  @spec generate_parameters(any()) :: binary()
  def generate_parameters(_) do
    :crypto.strong_rand_bytes(12)
  end

  def init_algo_state(key, aad, ctext_size, <<ivec::binary-size(12)>>) do
    GcmState256.new(key, aad, ctext_size, ivec)
  end

  def finish_ghash_calc(in_state) do
    {aad_l, ctext_l, ghash_val} = in_state.ghash_state
    ghash = :exmime_ghash.gcm_ghash_final_block(in_state.master_key,aad_l,ctext_l,ghash_val)
    :crypto.exor(ghash, in_state.eky0)
  end

  @spec run_gcm_step(Exmime.Aes.Gcm256.GcmState256.t(), <<_::128>>) ::
          {Exmime.Aes.Gcm256.GcmState256.t(), binary()}
  def run_gcm_step(in_state, <<plain_text::binary-size(16)>>) do
    <<iv0add::unsigned-big-integer-size(128)>> = in_state.current_ivec
    current_ivec = <<(iv0add + 1)::unsigned-big-integer-size(128)>>
    {new_state, eKY1xor} = :crypto.stream_encrypt(in_state.stream_state, current_ivec)
    eKY1 = :crypto.exor(eKY1xor, current_ivec)
    c_text = :crypto.exor(plain_text, eKY1)
    {_, _, ghash} = in_state.ghash_state
    bghash = :exmime_ghash.gcm_ghash_multiply(:crypto.exor(ghash, c_text), in_state.master_key)
    {GcmState256.update(in_state, new_state, current_ivec, bghash), c_text}
  end

  def run_gcm_step(in_state, <<plain_text::binary>>) do
    p_size = byte_size(plain_text)
    <<iv0add::unsigned-big-integer-size(128)>> = in_state.current_ivec
    current_ivec = <<(iv0add + 1)::unsigned-big-integer-size(128)>>
    {new_state, eKY1xor} = :crypto.stream_encrypt(in_state.stream_state, current_ivec)
    <<eKY1::binary-size(p_size),_::binary>> = :crypto.exor(eKY1xor, current_ivec)
    {_, _, ghash} = in_state.ghash_state
    c_text = :crypto.exor(plain_text, eKY1)
    bghash = :exmime_ghash.gcm_ghash_multiply(:crypto.exor(ghash, :exmime_ghash.gcm_pad(c_text)), in_state.master_key)
    {GcmState256.update(in_state, new_state, current_ivec, bghash), c_text}
  end
end
