defmodule Oauth2Provider.Guardian.DynamicSecretFetcher do
  use Guardian.Token.Jwt.SecretFetcher

  def fetch_signing_secret(_impl_module, opts) do
    {:ok, Keyword.get(opts, :secret, JwkProvider.get_private_jwk!())}
  end

  def fetch_verifying_secret(_impl_module, %{"kid" => hkid} = _token_headers, opts) do
    {:ok, %{"keys" => [default_jwk | _] = jwks}} = JwkProvider.get_public_jwks()

    jwk =
      Keyword.get_lazy(
        opts,
        :secret,
        fn -> Enum.find(jwks, default_jwk, fn %{"kid" => kid} -> kid == hkid end) end
      )

    {:ok, jwk}
  end

  def fetch_verifying_secret(_impl_module, _token_headers, _opts) do
    {:ok, %{"keys" => [jwk | _]}} = JwkProvider.get_public_jwks()
    {:ok, jwk}
  end

  def jwt_key_headers(%{"kid" => kid}),
    do: %{
      "kid" => kid,
      "jku" => "#{Confex.fetch_env!(:oauth2_provider, :pki_url)}/#{kid}/jwks"
    }

  def jwt_key_headers(_), do: %{}
end
