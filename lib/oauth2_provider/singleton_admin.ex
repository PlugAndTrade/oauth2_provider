defmodule Oauth2Provider.SingletonAdmin do
  @behaviour Oauth2Provider.Authenticatable

  @type t :: %__MODULE__{
          id: String.t(),
          username: String.t()
        }

  @id UUID.uuid4()

  @derive Jason.Encoder
  defstruct [:id, :username]

  def new(),
    do: %__MODULE__{id: @id, username: "admin"}

  @impl Oauth2Provider.Authenticatable
  def find_by_claims(%{"sub" => id}),
    do: {:ok, %__MODULE__{id: id, username: "admin"}}

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(%{"username" => "admin", "password" => password} = params) do
    admin_pwd = Elixir.Confex.get_env(:oauth2_provider, __MODULE__) |> Keyword.fetch!(:password)

    case String.length(admin_pwd) > 0 and password == admin_pwd do
      true -> {:ok, new(), Map.drop(params, ["username", "password"])}
      false -> {:error, %{message: "Authentication failed", code: "ERR_UNAUTHORIZED"}}
    end
  end

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(_),
    do: {:error, %{message: "Authentication failed", code: "ERR_UNAUTHORIZED"}}

  @impl Oauth2Provider.Authenticatable
  def is_admin?(_), do: true

  defimpl Oauth2Provider.Authenticatable.TokenResource do
    def claims(%Oauth2Provider.SingletonAdmin{username: username}, _typ),
      do: %{"username" => username}

    def sub(%Oauth2Provider.SingletonAdmin{id: id}), do: {:ok, id}
  end
end
