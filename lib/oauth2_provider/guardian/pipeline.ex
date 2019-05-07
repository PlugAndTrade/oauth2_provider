defmodule Oauth2Provider.Guardian.Pipeline do
  use Guardian.Plug.Pipeline,
    otp_app: :auth_me,
    error_handler: Oauth2Provider.Guardian.ErrorHandler,
    module: Oauth2Provider.Guardian

  # If there is a session token, restrict it to an access token and validate it
  plug(Guardian.Plug.VerifySession, claims: %{"typ" => "access"})
  # If there is an authorization header, restrict it to an access token and validate it
  plug(Guardian.Plug.VerifyHeader, claims: %{"typ" => "access"})
  plug(Guardian.Plug.EnsureAuthenticated, claims: %{"typ" => "access"})
  plug(Guardian.Plug.LoadResource)
end
