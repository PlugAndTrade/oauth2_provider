defmodule Oauth2Provider.HTTP.AppControllerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Oauth2Provider.Test.Helpers.ControllerHelper
  import Oauth2Provider.Test.Helpers.DBHelper

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Oauth2Provider.Repo)
  end

  test "create app success" do
    {:ok, %{id: client_id}} = create_client()

    {:ok, user} = Oauth2Provider.Test.User.new()

    conn =
      conn(:post, "/apps", %{"client_id" => client_id, "scopes" => ["openid", "a", "b"]})
      |> Oauth2Provider.Guardian.Plug.sign_in(user)
      |> Oauth2Provider.HTTP.Router.call([])

    %{id: user_id} = Oauth2Provider.Guardian.Plug.current_resource(conn)

    assert 201 == conn.status
    data = sent_json_resp(conn)

    assert %{
             "client_id" => ^client_id,
             "name" => "test_client",
             "scopes" => ["openid", "a", "b"],
             "user_id" => ^user_id,
             "id" => _
           } = data

    assert ["client_id", "id", "name", "scopes", "user_id"] == Map.keys(data)
  end

  test "create app redirect" do
    {:ok, %{id: client_id}} = create_client()

    params = %{
      "verify_url" => "http://verify_url/verify?client_id=asdf",
      "client_id" => client_id,
      "scopes" => ["openid", "a", "b"]
    }

    {:ok, user} = Oauth2Provider.Test.User.new()

    conn =
      conn(:post, "/apps", params)
      |> Oauth2Provider.Guardian.Plug.sign_in(user)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 302 == conn.status
    assert ["http://verify_url/verify?client_id=asdf"] = get_resp_header(conn, "location")
  end

  test "create app not authenticated" do
    {:ok, %{id: client_id}} = create_client()

    params = %{
      "verify_url" => "http://verify_url/verify?client_id=asdf",
      "client_id" => client_id,
      "scope" => "a b"
    }

    conn =
      conn(:post, "/apps", params)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 302 == conn.status
    assert ["/token?" <> _params] = get_resp_header(conn, "location")
  end

  test "verify authorization success" do
    {:ok, %{id: client_id}} = create_client()

    {:ok, %{id: user_id} = user} = Oauth2Provider.Test.User.new()

    {:ok, _app} = create_app(client_id, user_id)

    params = %{
      "client_id" => client_id,
      "scope" => "openid a b",
      "redirect_uri" => "http://test_client/callback",
      "state" => "asdf",
      "response_type" => "code"
    }

    conn =
      conn(:get, "/apps/verify", params)
      |> Oauth2Provider.Guardian.Plug.sign_in(user)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 302 == conn.status

    assert [
             "http://test_client/callback?authorization_code=" <>
               <<token::bytes-size(36)>> <> "&state=asdf"
           ] = get_resp_header(conn, "location")
  end

  test "verify authorization not authenticated" do
    {:ok, %{id: client_id}} = create_client()

    {:ok, %{id: user_id}} = Oauth2Provider.Test.User.new()

    {:ok, _app} = create_app(client_id, user_id)

    params = %{
      "client_id" => client_id,
      "scope" => "a b",
      "redirect_uri" => "http://test_client/callback",
      "state" => "asdf",
      "response_type" => "code"
    }

    conn =
      conn(:get, "/apps/verify", params)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 302 == conn.status
    assert ["/token?" <> _params] = get_resp_header(conn, "location")
  end
end
