defmodule Oauth2Provider.Test.User do
  @behaviour Oauth2Provider.Authenticatable

  @type t :: %__MODULE__{
          id: String.t(),
          username: String.t()
        }

  @derive Jason.Encoder
  defstruct [:id, :username]

  def new(),
    do: {:ok, %__MODULE__{id: UUID.uuid4(), username: "test"}}

  @impl Oauth2Provider.Authenticatable
  def find_by_claims(%{"sub" => id}),
    do: {:ok, %__MODULE__{id: id, username: "test"}}

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(%{"username" => "test"} = params),
    do: {:ok, %__MODULE__{id: UUID.uuid4(), username: "test"}, Map.drop(params, ["username"])}

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(_),
    do: {:error, %{message: "No such user found", code: "ERR_NOT_FOUND"}}

  defimpl Oauth2Provider.Authenticatable.TokenResource do
    def claims(%Oauth2Provider.Test.User{username: username}),
      do: %{"username" => username}

    def sub(%Oauth2Provider.Test.User{id: id}), do: {:ok, id}
  end

  def init_login(conn, _params) do
      conn
      |> Plug.Conn.put_resp_content_type("text/plain")
      |> Plug.Conn.send_resp(:ok, "OK")
  end
end
