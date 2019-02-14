defmodule Exmime.RsaTestHelpers do
  require Exmime.Records

  def read_private_key() do
    {:ok, f} = :file.open("example.com.key", [:binary, :read])
    {:ok, f_data} = :file.read(f, 82174)
    [entry] = :public_key.pem_decode(f_data)
    :public_key.pem_entry_decode(entry)
  end

  def extract_cert_props() do
    {:ok, f} = :file.open("example.com.crt", [:binary, :read])
    {:ok, f_data} = :file.read(f, 82174)
    [entry] = :public_key.pem_decode(f_data)
    pem_entry = :public_key.pem_entry_decode(entry)
    cert_serial = Exmime.Certificate.extract_serial_number(pem_entry)
    [modulus, public_exp] = Exmime.Certificate.extract_rsa_public_key(pem_entry)
    rsa_pubkey_record = Exmime.Records.'RSAPublicKey'(
      modulus: modulus,
      publicExponent: public_exp
    )
    {cert_serial, rsa_pubkey_record}
  end
end
