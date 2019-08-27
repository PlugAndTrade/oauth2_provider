defmodule Oauth2Provider.Repo.Migrations.AddClientNoauth do
  use Ecto.Migration

  def change do
    alter table(:clients) do
      add :allow_noauth, :boolean, default: false, null: false
    end
  end
end
