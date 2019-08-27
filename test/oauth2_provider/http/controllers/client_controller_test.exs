defmodule Oauth2Provider.HTTP.ClientControllerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Oauth2Provider.Test.Helpers.ControllerHelper

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Oauth2Provider.Repo)
  end

  test "create client success" do
    params = %{
      "name" => "test_client_name",
      "redirect_uris" => ["http://localhost:3000/callback"]
    }

    admin = Oauth2Provider.SingletonAdmin.new()

    conn =
      conn(:post, "/clients", params)
      |> Oauth2Provider.Guardian.Plug.sign_in(admin)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 201 == conn.status
    assert %{
      "id" => client_id,
      "secret" => secret,
      "name" => "test_client_name",
      "redirect_uris" => ["http://localhost:3000/callback"]
    } = sent_json_resp(conn)

    assert {:ok, %{
      secret: hashed_secret} = client
    } = Oauth2Provider.Repo.fetch(Oauth2Provider.Client, client_id)
    assert :verified == Crypto.verify_password(Base.decode64!(hashed_secret), secret)
  end

  test "create client not admin" do
    params = %{
      "name" => "test_client_name",
      "redirect_uris" => ["http://localhost:3000/callback"]
    }

    {:ok, user} = Oauth2Provider.Test.User.new()

    conn =
      conn(:post, "/clients", params)
      |> Oauth2Provider.Guardian.Plug.sign_in(user)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 403 == conn.status
    assert %{"errors" => [_]} = sent_json_resp(conn)
  end
end
