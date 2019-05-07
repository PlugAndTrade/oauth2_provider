defmodule Oauth2Provider.App do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :string, []}
  schema "apps" do
    field(:name, :string)
    field(:scopes, {:array, :string})
    field(:client_id, :string)
    field(:user_id, :string)
  end

  def changeset(params), do: changeset(%__MODULE__{}, params)

  def changeset(client, params) do
    client
    |> cast(params, [:name, :scopes, :client_id, :user_id])
    |> cast(%{id: UUID.uuid4()}, [:id])
    |> validate_required([:id, :name, :scopes, :client_id, :user_id])
  end
end
