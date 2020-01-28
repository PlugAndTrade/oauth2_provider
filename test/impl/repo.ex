defmodule Oauth2Provider.TestRepo do
  require Ecto.Query

  use Ecto.Repo,
    otp_app: :oauth2_provider,
    adapter: Ecto.Adapters.Postgres
end
