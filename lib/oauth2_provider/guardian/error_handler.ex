defmodule Oauth2Provider.Guardian.ErrorHandler do
  use Oauth2Provider.HTTP.Controller

  @behaviour Guardian.Plug.ErrorHandler

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {_type, %{code: "ERR_ELASTIC_REFUSED"} = error}, _opts) do
    Logger.error(inspect(error))
    json(conn, 500, error)
  end

  @impl Guardian.Plug.ErrorHandler
  def auth_error(%Plug.Conn{} = conn, {type, reason}, opts) do
    params = Map.take(conn.query_params, ["provider"])

    query =
      %{"redirect_to" => URI.encode_www_form(request_url(conn))}
      |> Map.merge(params)
      |> URI.encode_query()

    Logger.error("auth_error #{inspect({type, reason, opts})}")

    conn
    |> put_resp_header(
      "location",
      "#{Confex.fetch_env!(:oauth2_provider, :path_prefix)}/token?#{query}"
    )
    |> send_resp(302, "")
  end
end
