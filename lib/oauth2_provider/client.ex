defmodule Oauth2Provider.Client do
  use Ecto.Schema
  import Ecto.Changeset

  @derive {Jason.Encoder, only: [:id, :name, :redirect_uris, :allow_noauth]}

  @primary_key {:id, :string, []}
  schema "clients" do
    field(:name, :string)
    field(:secret, :string)
    field(:redirect_uris, {:array, :string})
    field(:allow_noauth, :boolean)
  end

  def changeset(params), do: changeset(%__MODULE__{}, params)

  def changeset(client, params) do
    client
    |> cast(params, [:name, :redirect_uris, :secret, :allow_noauth])
    |> cast(%{id: UUID.uuid4()}, [:id])
    |> validate_required([:id, :name, :secret, :redirect_uris])
  end
end
