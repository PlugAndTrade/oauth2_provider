defmodule Oauth2Provider.HTTP.ClientControllerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Oauth2Provider.Test.Helpers.ControllerHelper
  import Oauth2Provider.Test.Helpers.DBHelper

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Oauth2Provider.Test.Repo)
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
      "redirect_uris" => ["http://localhost:3000/callback"],
      "allow_noauth" => false
    } = sent_json_resp(conn)

    assert {:ok, %{
      secret: hashed_secret
    } = client} = Oauth2Provider.Store.fetch(Oauth2Provider.Client, client_id)
    assert :verified == Crypto.verify_password(Base.decode64!(hashed_secret), secret)
  end

  test "create client allow_noauth" do
    params = %{
      "name" => "test_client_name",
      "redirect_uris" => ["http://localhost:3000/callback"],
      "allow_noauth" => "true"
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
      "redirect_uris" => ["http://localhost:3000/callback"],
      "allow_noauth" => true
    } = sent_json_resp(conn)

    assert {:ok, %{
      secret: hashed_secret
    } = client} = Oauth2Provider.Store.fetch(Oauth2Provider.Client, client_id)
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

  test "list clients" do
    {:ok, %{id: client_id_1}} = create_client()
    {:ok, %{id: client_id_2}} = create_client()
    {:ok, %{id: client_id_3}} = create_client()

    admin = Oauth2Provider.SingletonAdmin.new()

    conn =
      conn(:get, "/clients")
      |> Oauth2Provider.Guardian.Plug.sign_in(admin)
      |> Oauth2Provider.HTTP.Router.call([])

    assert %{"clients" => clients} = sent_json_resp(conn)
    assert clients |> Enum.map(&Map.get(&1, "secret")) |> Enum.all?(&is_nil/1)

    ids = Enum.map(clients, &Map.get(&1, "id"))
    assert client_id_1 in ids
    assert client_id_2 in ids
    assert client_id_3 in ids
  end
end
