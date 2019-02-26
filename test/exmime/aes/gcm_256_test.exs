defmodule Exmime.Aes.Gcm256Test do
  use ExUnit.Case
  doctest Exmime.Aes.Gcm256

  test "creates and verifies correctly" do
      data1 = "0123456789ABCDEF"
      data2 = "02"

      # Key, IVec, AAD
      key = Exmime.Aes.Gcm256.generate_key()
      ivec = Exmime.Aes.Gcm256.generate_parameters(key)
      aad = :crypto.strong_rand_bytes(12)
      algo_state = Exmime.Aes.Gcm256.init_algo_state(key, aad, byte_size(data1 <> data2), ivec)

      # Process first block
      {new_state, my_data1} = Exmime.Aes.Gcm256.run_gcm_step(algo_state, data1)
      # Process second block
      {new_state2, my_data2} = Exmime.Aes.Gcm256.run_gcm_step(new_state, data2)
      # Complete tag calculation
      data_tag = Exmime.Aes.Gcm256.finish_ghash_calc(new_state2)


      # Normal erlang implementation
      {reference_ct, reference_tag} = :crypto.block_encrypt(:aes_gcm,key,ivec,{aad, data1<>data2})
      ^reference_ct = my_data1<>my_data2
      ^reference_tag = data_tag
      IO.inspect({my_data1<>my_data2, data_tag})
      IO.inspect({reference_ct, reference_tag})
  end
end
