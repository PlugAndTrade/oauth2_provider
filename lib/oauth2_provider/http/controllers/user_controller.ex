defmodule Oauth2Provider.HTTP.UserController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug

  def get(conn, _params) do
    claims = current_claims(conn)
    conn
    |> put_no_cache_headers()
    |> json(200, claims)
  end
end
