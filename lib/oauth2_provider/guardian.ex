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
end
