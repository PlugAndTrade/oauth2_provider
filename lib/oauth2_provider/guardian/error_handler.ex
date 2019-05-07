defmodule Oauth2Provider.Guardian.ErrorHandler do
  use Oauth2Provider.HTTP.Controller

  @behaviour Guardian.Plug.ErrorHandler

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {_type, %{code: "ERR_ELASTIC_REFUSED"} = error}, _opts) do
    Logger.error(inspect(error))
    json(conn, 500, error)
  end

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {type, reason}, opts) do
    Logger.error("auth_error #{inspect({type, reason, opts})}")

    conn
    |> put_resp_header(
      "location",
      "/token?redirect_to=#{URI.encode_www_form(request_url(conn))}"
    )
    |> send_resp(302, "")
  end
end
