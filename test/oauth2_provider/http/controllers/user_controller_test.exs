defmodule Oauth2Provider.HTTP.UserControllerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Oauth2Provider.Test.Helpers.ControllerHelper
  import Oauth2Provider.Test.Helpers.DBHelper

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Oauth2Provider.Repo)
  end

  test "unauthenticated" do
    conn =
      conn(:get, "/users/me", %{})
      |> Oauth2Provider.HTTP.Router.call([])

    assert 302 == conn.status
    assert ["/token?" <> _params] = get_resp_header(conn, "location")
  end

  test "get user data as app actor" do
    {:ok, %{id: client_id} = client} = create_client()

    {:ok, user} = Oauth2Provider.Test.User.new()

    {:ok, app} =
      %{client_id: client_id, name: "test_client", user_id: user.id, scopes: ["a", "b"]}
      |> Oauth2Provider.App.changeset()
      |> Oauth2Provider.Repo.insert()

    app_actor = Oauth2Provider.AppActor.new(app, client, user)

    conn =
      conn(:get, "/users/me", %{})
      |> Oauth2Provider.Guardian.Plug.sign_in(app_actor)
      |> Oauth2Provider.HTTP.Router.call([])

    assert 200 == conn.status
    data = sent_json_resp(conn)

    assert %{
             "sub" => user.id,
             "subType" => "user",
             "username" => user.username
           } == data
    assert ["no-store"] = get_resp_header(conn, "cache-control")
    assert ["no-cache"] = get_resp_header(conn, "pragma")
  end
end
