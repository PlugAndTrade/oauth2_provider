defmodule Oauth2Provider.Repo.Migrations.AddAppsTable do
  use Ecto.Migration

  def change do
    create table(:apps, primary_key: false) do
      add :id, :string, primary_key: true
      add :name, :string
      add :scopes, {:array, :string}
      add :client_id, :string
      add :user_id, :string
    end
  end
end
