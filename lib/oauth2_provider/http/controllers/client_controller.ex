defmodule Oauth2Provider.HTTP.ClientController do
  require Logger

  def create(conn, params) do
    with create_params <- validate_create(params),
         {secret, secret_hash} <- generate_secret(),
         changeset <-
           Oauth2Provider.Client.changeset(Map.merge(create_params, %{secret: secret_hash})),
         {:ok, client} <- Oauth2Provider.Repo.insert(changeset) do
      Plug.Conn.send_resp(conn, 200, Poison.encode!(%{client | secret: secret}))
    else
      {:error, err} ->
        Logger.error(inspect(err))
        Plug.Conn.send_resp(conn, 400, "Error")

      err ->
        Logger.error(inspect(err))
        Plug.Conn.send_resp(conn, 400, "Error")
    end
  end

  def generate_secret() do
    secret = :crypto.strong_rand_bytes(24) |> Base.url_encode64()
    secret_hash = Crypto.create_hash(secret) |> Base.encode64()
    {secret, secret_hash}
  end

  def validate_create(%{"name" => name, "redirectURIs" => redirect_uris}) do
    %{name: name, redirect_uris: redirect_uris}
  end
end
