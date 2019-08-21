defmodule Oauth2Provider.HTTP.Controller do
  defmacro __using__(_opts) do
    quote do
      import Plug.Conn
      import Oauth2Provider.HTTP.Controller
      require Logger
    end
  end

  def json(conn, status, data),
    do:
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status, Jason.encode!(data))

  def add_query_params(%URI{query: nil} = uri, params),
    do: URI.to_string(%{uri | query: URI.encode_query(params)})

  def add_query_params(%URI{query: query} = uri, params),
    do: URI.to_string(%{uri | query: query |> URI.decode_query(params) |> URI.encode_query()})

  def add_query_params(uri, params), do: add_query_params(URI.parse(uri), params)
end
