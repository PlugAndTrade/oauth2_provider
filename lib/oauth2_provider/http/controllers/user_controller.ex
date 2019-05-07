defmodule Oauth2Provider.HTTP.UserController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug

  def get(conn, _params) do
    actor = current_resource(conn)

    case get_user(actor) do
      {:ok, user} -> json(conn, 200, user)
      {:error, error} -> json(conn, 400, error)
    end
  end

  defp get_user(%Oauth2Provider.AppActor{user: user}) do
    {:ok, user}
  end

  defp get_user(_) do
    {:error, %{code: "ERR_UNAUTHORIZED", message: "Not authorized"}}
  end
end
