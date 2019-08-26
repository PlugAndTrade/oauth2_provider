defmodule Oauth2Provider.Repo do
  require Ecto.Query
  use Ecto.Repo,
    otp_app: :oauth2_provider,
    adapter: Ecto.Adapters.Postgres

  def fetch(mod, id) do
    case Oauth2Provider.Repo.get(mod, id) do
      nil -> {:error, %{code: "ERR_NOT_FOUND", message: "Resource not found"}}
      app -> {:ok, app}
    end
  end

  def search_one(mod, clauses) do
    case Oauth2Provider.Repo.all(filter_to_query(mod, clauses)) do
      [] -> {:error, %{code: "ERR_NOT_FOUND", message: "Resource not found"}}
      [app] -> {:ok, app}
      _ -> {:error, %{code: "ERR_MULTIPLE_FOUND", message: "Found multiple resources matching the query"}}
    end
  end

  defp filter_to_query(mod, clauses) do
    Ecto.Query.from(
      r in mod,
      where: ^clauses,
      select: r
    )
  end
end
