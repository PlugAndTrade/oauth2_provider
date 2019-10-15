use Mix.Config

config :oauth2_provider, ecto_repos: [Oauth2Provider.TestRepo]

config :oauth2_provider, Oauth2Provider.Store,
  repo: Oauth2Provider.TestRepo

config :oauth2_provider, Oauth2Provider.TestRepo,
  database: "oauth2_provider",
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: "5432",
  pool: Ecto.Adapters.SQL.Sandbox

config :oauth2_provider,
  init_login: {Oauth2Provider.Test.User, :init_login},
  html: []
