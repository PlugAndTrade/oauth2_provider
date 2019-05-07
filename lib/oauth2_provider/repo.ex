defmodule Oauth2Provider.Repo do
  use Ecto.Repo,
    otp_app: :oauth2_provider,
    adapter: Ecto.Adapters.Postgres

  def fetch(mod, id) do
    case Oauth2Provider.Repo.get(mod, id) do
      nil -> {:error, %{code: "ERR_NOT_FOUND", message: "App not found"}}
      app -> {:ok, app}
    end
  end
end
