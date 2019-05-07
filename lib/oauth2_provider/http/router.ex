defmodule Oauth2Provider.HTTP.Router do
  use Plug.Router
  use Plug.ErrorHandler
  require Logger

  plug(Plug.Logger,
    log: :debug
  )

  plug(:match)

  plug(Plug.Parsers,
    parsers: [:json, :urlencoded],
    pass: ["application/json", "application/x-www-form-urlencoded"],
    json_decoder: Poison
  )

  plug(Plug.Session,
    store: :ets,
    key: Elixir.Confex.get_env(:oauth2_provider, :session) |> Keyword.fetch!(:key),
    table: Elixir.Confex.get_env(:oauth2_provider, :session) |> Keyword.fetch!(:table)
  )

  plug(:dispatch)

  forward("/token", to: Oauth2Provider.HTTP.TokenRoutes)
  forward("/apps", to: Oauth2Provider.HTTP.AppRoutes)
  forward("/users", to: Oauth2Provider.HTTP.UserRoutes)
  forward("/clients", to: Oauth2Provider.HTTP.ClientRoutes)

  match _ do
    send_resp(conn, 404, "Not Found")
  end
end
