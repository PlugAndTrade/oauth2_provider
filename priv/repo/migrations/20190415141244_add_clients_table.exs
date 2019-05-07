defmodule Oauth2Provider.Repo.Migrations.AddClientsTable do
  use Ecto.Migration

  def change do
    create table(:clients, primary_key: false) do
      add :id, :string, primary_key: true
      add :name, :string
      add :secret, :string
      add :redirect_uris, {:array, :string}
    end
  end
end
