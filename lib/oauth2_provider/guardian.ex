defmodule Oauth2Provider.Guardian do
  use Guardian, otp_app: :oauth2_provider

  def subject_for_token(res, _claims), do: Oauth2Provider.Authenticatable.TokenResource.sub(res)

  def resource_from_claims(%{"sub" => sub, "subType" => type}) do
    with {:ok, impl} <- Oauth2Provider.Authenticatable.get_impl_from_type(type) do
      impl.find_by_subject(sub)
    else
      err -> err
    end
  end

  def resource_from_claims(_claims), do: {:error, :unknown_token_subject}
end
