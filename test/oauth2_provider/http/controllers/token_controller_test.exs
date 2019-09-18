defmodule Oauth2Provider.HTTP.TokenControllerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Oauth2Provider.Test.Helpers.ControllerHelper
  import Oauth2Provider.Test.Helpers.DBHelper

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Oauth2Provider.TestRepo)
  end

  test "get init login response" do
    conn =
      conn(:get, "/token")
      |> Oauth2Provider.HTTP.Router.call([])

    assert 200 == conn.status
    assert ["text/plain" <> _charset] = get_resp_header(conn, "content-type")
    assert {_status, _headers, "OK"} = sent_resp(conn)
  end

  test "create app access token" do
    secret = :crypto.strong_rand_bytes(24) |> Base.url_encode64()
    {:ok, %{id: client_id, redirect_uris: [redirect_uri | _]}} = create_client(secret: secret)

    {:ok, %{id: user_id} = user} = Oauth2Provider.Test.User.new()

    {:ok, %{id: app_id}} = create_app(client_id, user_id)

    %{id: code} = token = Oauth2Provider.Token.new(
      app_id: app_id,
      resource_claims: Oauth2Provider.Authenticatable.claims_from_resource(user, "access")
    )
    Oauth2Provider.Token.Registry.put(:token_registry, token)

    params = %{
      "client_id" => client_id,
      "client_secret" => secret,
      "redirect_uri" => redirect_uri,
      "code" => code,
      "grant_type" => "code",
      "type" => "app"
    }

    conn =
      conn(:post, "/token/app", params)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 201 == conn.status
    data = sent_json_resp(conn)
    assert %{
      "access_token" => jwt,
      "token_type" => "Bearer",
      "expires_in" => ttl
    } = data
    assert {:ok, %{
      "typ" => "access",
      "sub" => ^user_id,
      "username" => "test",
      "azp" => ^client_id,
      "client_id" => ^client_id,
      "urn:pnt:oauth2:sub_typ" => "app",
      "urn:pnt:oauth2:resource_typ" => "user",
      "aud" => ["oauth2_provider", ^client_id],
      "scope" => "openid a b"
    }} = Oauth2Provider.Guardian.decode_and_verify(jwt)
    assert ["no-store"] = get_resp_header(conn, "cache-control")
    assert ["no-cache"] = get_resp_header(conn, "pragma")
  end

  test "create app access token bad secret" do
    secret = :crypto.strong_rand_bytes(24) |> Base.url_encode64()
    {:ok, %{id: client_id, redirect_uris: [redirect_uri | _]}} = create_client(secret: secret)

    {:ok, %{id: user_id} = user} = Oauth2Provider.Test.User.new()

    {:ok, %{id: app_id}} = create_app(client_id, user_id)

    %{id: code} = token = Oauth2Provider.Token.new(
      app_id: app_id,
      resource_claims: Oauth2Provider.Authenticatable.claims_from_resource(user, "access")
    )
    Oauth2Provider.Token.Registry.put(:token_registry, token)

    params = %{
      "client_id" => client_id,
      "client_secret" => :crypto.strong_rand_bytes(24) |> Base.url_encode64(),
      "redirect_uri" => redirect_uri,
      "code" => code,
      "grant_type" => "code",
      "type" => "app"
    }

    conn =
      conn(:post, "/token/app", params)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 401 == conn.status
    data = sent_json_resp(conn)

    assert %{"errors" => [%{"message" => "Authentication failed", "code" => "ERR_UNAUTHORIZED"}]} ==
             data
  end

  test "create app access token incorrect redirect_uri" do
    secret = :crypto.strong_rand_bytes(24) |> Base.url_encode64()
    {:ok, %{id: client_id}} = create_client(secret: secret)

    {:ok, %{id: user_id} = user} = Oauth2Provider.Test.User.new()

    {:ok, %{id: app_id}} = create_app(client_id, user_id)

    %{id: code} = token = Oauth2Provider.Token.new(
      app_id: app_id,
      resource_claims: Oauth2Provider.Authenticatable.claims_from_resource(user, "access")
    )
    Oauth2Provider.Token.Registry.put(:token_registry, token)

    params = %{
      "client_id" => client_id,
      "client_secret" => secret,
      "redirect_uri" => "incorrect_uri",
      "code" => code,
      "grant_type" => "code",
      "type" => "app"
    }

    conn =
      conn(:post, "/token/app", params)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 401 == conn.status
    data = sent_json_resp(conn)

    assert %{"errors" => [%{"message" => "Authentication failed", "code" => "ERR_UNAUTHORIZED"}]} ==
             data
  end

  test "create admin token" do
    pwd = :crypto.strong_rand_bytes(24) |> Base.url_encode64()
    Application.put_env(:oauth2_provider, Oauth2Provider.SingletonAdmin, [password: pwd])

    conn =
      conn(:post, "/token/admin", %{"username" => "admin", "password" => pwd})
      |> Oauth2Provider.HTTP.Router.call([])

    assert 201 == conn.status
    assert %{
      "access_token" => jwt,
      "token_type" => "Bearer",
      "expires_in" => ttl
    } = sent_json_resp(conn)
    assert ["no-store"] = get_resp_header(conn, "cache-control")
    assert ["no-cache"] = get_resp_header(conn, "pragma")
  end

  test "create admin token disallow emtpy password" do
    Application.put_env(:oauth2_provider, Oauth2Provider.SingletonAdmin, [password: ""])

    conn =
      conn(:post, "/token/admin", %{"username" => "admin", "password" => ""})
      |> Oauth2Provider.HTTP.Router.call([])

    assert 401 == conn.status
    assert %{"errors" => [_]} = sent_json_resp(conn)
  end

  test "get current access token" do
    {:ok, user} = Oauth2Provider.Test.User.new()

    conn =
      conn(:get, "/token/current")
      |> Oauth2Provider.Guardian.Plug.sign_in(user)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 200 == conn.status
    assert %{
      "access_token" => jwt,
      "token_type" => "Bearer",
      "expires_in" => ttl
    } = sent_json_resp(conn)
    assert ["no-store"] = get_resp_header(conn, "cache-control")
    assert ["no-cache"] = get_resp_header(conn, "pragma")
  end
end
