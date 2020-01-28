defmodule Mix.Tasks.Oauth2Provider.Gen.Migrations do
  use Mix.Task

  @changes [
    {
      "add_clients_table",
      """
          create table(:clients, primary_key: false) do
            add :id, :string, primary_key: true
            add :name, :string
            add :secret, :string
            add :redirect_uris, {:array, :string}
          end
      """
    },
    {
      "add_apps_table",
      """
          create table(:apps, primary_key: false) do
            add :id, :string, primary_key: true
            add :name, :string
            add :scopes, {:array, :string}
            add :client_id, :string
            add :user_id, :string
          end
      """
    },
    {
      "add_client_noauth",
      """
          alter table(:clients) do
            add :allow_noauth, :boolean, default: false, null: false
          end
      """
    }
  ]

  @shortdoc "Generates sql migrations for oauth2_provider"
  def run(_) do
    repo = Application.get_env(:oauth2_provider, Oauth2Provider.Store) |> Keyword.fetch!(:repo)
    Mix.Ecto.ensure_repo(repo, [])
    priv_path = Mix.EctoSQL.source_repo_priv(repo)

    @changes
    |> Enum.map(fn {name, change} ->
      existing = Path.join([priv_path, "migrations", "*_#{name}.exs"]) |> Path.wildcard()

      if existing != [] do
        Mix.shell().info("#{name} already created at #{List.first(existing)}")
      else
        # Ensure every subsequent migration has a larger timestamp
        :timer.sleep(1000)

        Mix.Tasks.Ecto.Gen.Migration.run([
          name,
          "-r",
          inspect(repo),
          "--change",
          change
        ])
      end
    end)
  end
end
