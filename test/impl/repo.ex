defmodule Oauth2Provider.Test.Repo do
  require Ecto.Query
  use Ecto.Repo,
    otp_app: :oauth2_provider,
    adapter: Ecto.Adapters.Postgres
end
