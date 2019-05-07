defmodule Oauth2Provider.Test.User do
  @behaviour Oauth2Provider.Authenticatable

  @type t :: %__MODULE__{
          id: String.t(),
          username: String.t()
        }

  defstruct [:id, :username]

  def new(),
    do: find_by_id(UUID.uuid4())

  @impl Oauth2Provider.Authenticatable
  def find_by_id(id),
    do: {:ok, %__MODULE__{id: id, username: "test"}}

  @impl Oauth2Provider.Authenticatable
  def find_by_subject(id),
    do: find_by_id(id)

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(%{"username" => "test"}),
    do: find_by_id(UUID.uuid4())

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(_),
    do: {:error, %{message: "No such user found", code: "ERR_NOT_FOUND"}}

  defimpl Oauth2Provider.Authenticatable.TokenResource do
    def claims(%Oauth2Provider.Test.User{username: username}),
      do: %{username: username}

    def sub(%Oauth2Provider.Test.User{id: id}), do: {:ok, id}
  end
end
