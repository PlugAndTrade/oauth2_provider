defmodule Oauth2Provider.Guardian do
  use Guardian, otp_app: :oauth2_provider

  def subject_for_token(res, _claims), do: Oauth2Provider.Authenticatable.TokenResource.sub(res)

  def resource_from_claims(claims) do
    Oauth2Provider.Authenticatable.find_by_claims(claims)
  end

  def build_claims(%{"typ" => typ} = claims, resource, _opts) do
    custom_claims = Oauth2Provider.Authenticatable.claims_from_resource(resource, typ)
    {:ok, Oauth2Provider.Authenticatable.merge_claims(claims, custom_claims)}
  end

  def generate_tokens(resource, claims \\ %{}) do
    with {:ok, secret} <- Oauth2Provider.Guardian.DynamicSecretFetcher.fetch_signing_secret(:some_impl, []),
         key_headers <- Oauth2Provider.Guardian.DynamicSecretFetcher.jwt_key_headers(secret),
         {:ok, access_token, claims} <- Oauth2Provider.Guardian.encode_and_sign(
           resource,
           claims,
           secret: secret,
           headers: key_headers,
           token_type: "access"
         ),
         {:ok, id_token, _} <- Oauth2Provider.Guardian.encode_and_sign(
           resource,
           claims,
           secret: secret,
           headers: key_headers,
           token_type: "id"
         ) do
      {:ok, access_token, id_token, claims}
    else
      {:error, err} -> {:error, err}
      err -> {:error, err}
    end
  end
end
