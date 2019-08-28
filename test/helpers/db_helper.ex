defmodule Oauth2Provider.Test.Helpers.DBHelper do
  def create_client(opts \\ []) do
    %{
      name: "test_client",
      redirect_uris: ["http://test_client/callback"],
      secret:
        opts
        |> Keyword.get(:secret, :crypto.strong_rand_bytes(24) |> Base.url_encode64())
        |> Crypto.create_hash()
        |> Base.encode64(),
      allow_noauth: Keyword.get(opts, :allow_noauth, false)
    }
    |> Oauth2Provider.Client.changeset()
    |> Oauth2Provider.Store.insert()
  end

  def create_app(client_id, user_id) do
    %{
      client_id: client_id,
      name: "test_client",
      user_id: user_id,
      scopes: ["openid", "a", "b"]
    }
    |> Oauth2Provider.App.changeset()
    |> Oauth2Provider.Store.insert()
  end
end
