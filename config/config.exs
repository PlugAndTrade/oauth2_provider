# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# This configuration is loaded before any dependency and is restricted
# to this project. If another project depends on this project, this
# file won't be loaded nor affect the parent project. For this reason,
# if you want to provide default values for your application for
# third-party users, it should be done in your "mix.exs" file.

# You can configure your application as:
#
#     config :ecom_oauth2_legacy, key: :value
#
# and access this configuration in your application as:
#
#     Application.get_env(:ecom_oauth2_legacy, :key)
#
# You can also configure a third-party app:
#
#     config :logger, level: :info
#

config :oauth2_provider,
  path_prefix: {:system, "OAUTH2_PATH_PREFIX", ""},
  pki_url: "http://localhost:4000/pki",
  session: [
    key: "oauth2_provider",
    table: :session
  ],
  init_login: &Oauth2Provider.HTTP.TokenController.login_html_template/2,
  html: [
    authorize_form: "./test/impl/templates/authorize_form.html",
    login_form: "./test/impl/templates/login_form.html"
  ]

config :oauth2_provider, Oauth2Provider.SingletonAdmin,
  password: ""

config :oauth2_provider, Oauth2Provider.Authenticatable,
  [
    modules: %{
      "user" => Oauth2Provider.Test.User,
      "admin" => Oauth2Provider.SingletonAdmin,
      "app" => Oauth2Provider.AppActor
    }
  ]

config :oauth2_provider, ecto_repos: [Oauth2Provider.Repo]

config :oauth2_provider, Oauth2Provider.Repo,
  database: "oauth2_provider",
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: "5432"

config :oauth2_provider, Oauth2Provider.Guardian,
  allowed_algos: ["RS256"],
  issuer: "oauth2_provider",
  ttl: {1, :weeks},
  secret_fetcher: Oauth2Provider.Guardian.DynamicSecretFetcher

# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
import_config "#{Mix.env()}.exs"
