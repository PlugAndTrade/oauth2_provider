defmodule Oauth2Provider.Guardian do
  use Guardian, otp_app: :oauth2_provider

  def subject_for_token(res, _claims), do: Oauth2Provider.Authenticatable.TokenResource.sub(res)

  def resource_from_claims(claims) do
    Oauth2Provider.Authenticatable.find_by_claims(claims)
  end
end
