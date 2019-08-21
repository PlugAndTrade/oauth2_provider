defmodule Oauth2Provider.Test.Helpers.ControllerHelper do
  use Plug.Test
  import ExUnit.Assertions

  def sent_json_resp(conn) do
    {_status, _headers, json} = sent_resp(conn)
    assert ["application/json" <> _charset] = get_resp_header(conn, "content-type")
    assert {:ok, data} = Jason.decode(json)
    data
  end
end
