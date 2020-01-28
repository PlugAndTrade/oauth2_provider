defmodule Oauth2Provider.Store do
  require Ecto.Query
  @repo Application.get_env(:oauth2_provider, __MODULE__) |> Keyword.fetch!(:repo)

  def insert(changeset), do: @repo.insert(changeset)
  def all(mod), do: @repo.all(mod)
  def get_by(mod, filter), do: @repo.get_by(mod, filter)
  def get(mod, id), do: @repo.get(mod, id)

  def fetch(mod, id) do
    case @repo.get(mod, id) do
      nil -> {:error, %{code: "ERR_NOT_FOUND", message: "Resource not found"}}
      app -> {:ok, app}
    end
  end

  def search_one(mod, clauses) do
    case @repo.all(filter_to_query(mod, clauses)) do
      [] ->
        {:error, %{code: "ERR_NOT_FOUND", message: "Resource not found"}}

      [app] ->
        {:ok, app}

      _ ->
        {:error,
         %{code: "ERR_MULTIPLE_FOUND", message: "Found multiple resources matching the query"}}
    end
  end

  defp filter_to_query(mod, clauses) do
    Ecto.Query.from(
      r in mod,
      where: ^clauses,
      select: r
    )
  end

  def repo, do: @repo
end
