defmodule Oauth2Provider.Client do
  use Ecto.Schema
  import Ecto.Changeset

  @repo Oauth2Provider.Repo

  @derive {Jason.Encoder, only: [:id, :name, :redirect_uris]}

  @primary_key {:id, :string, []}
  schema "clients" do
    field(:name, :string)
    field(:secret, :string)
    field(:redirect_uris, {:array, :string})
  end

  def changeset(params), do: changeset(%__MODULE__{}, params)

  def changeset(client, params) do
    client
    |> cast(params, [:name, :redirect_uris, :secret])
    |> cast(%{id: UUID.uuid4()}, [:id])
    |> validate_required([:id, :name, :secret, :redirect_uris])
  end

  def get(id) do
    case @repo.get(__MODULE__, id) do
      nil -> {:error, %{code: "ERR_NOT_FOUND", message: "Client not found"}}
      client -> {:ok, client}
    end
  end
end
