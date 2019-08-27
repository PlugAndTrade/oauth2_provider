defmodule Oauth2Provider.HTTP.UserController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug

  def get(conn, _params) do
    actor = current_resource(conn)

    case get_user(conn, actor) do
      {:error, error} -> json(conn, 400, error)
      user -> json(conn, 200, user)
    end
  end

  defp get_user(_conn, %Oauth2Provider.AppActor{user: resource}),
    do: Oauth2Provider.Authenticatable.claims_from_resource(resource, "access")

  defp get_user(conn, resource),
    do: Oauth2Provider.Authenticatable.claims_from_resource(resource, "access")
    |> Map.merge(%{"access_token" => current_token(conn)})
end
