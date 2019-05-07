defmodule Crypto do
  def verify_password(<<0::size(8), salt::binary-size(16), hpwd::binary-size(32)>> = _hash, pwd) do
    case hash_password(pwd, salt) do
      ^hpwd -> :verified
      _ -> :not_verified
    end
  end

  def create_hash(pwd),
    do: create_hash(pwd, :crypto.strong_rand_bytes(16))

  def create_hash(pwd, <<_::binary-size(16)>> = salt),
    do: <<0::size(8)>> <> salt <> hash_password(pwd, salt)

  def hash_password(pwd, salt),
    do: Plug.Crypto.KeyGenerator.generate(pwd, salt, digest: :sha, length: 32, iterations: 1000)
end
