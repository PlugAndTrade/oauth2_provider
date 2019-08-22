use Mix.Config

config :oauth2_provider, Oauth2Provider.Repo,
  database: "oauth2_provider",
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: "5432",
  pool: Ecto.Adapters.SQL.Sandbox

config :oauth2_provider,
  init_login: &Oauth2Provider.Test.User.init_login/2,
  html: []

config :jwk_provider, :provider,
  {:system, :atom, "JWK_PROVIDER", :fs}

config :jwk_provider, JwkProvider.FileSystem,
  public_key: {:system, "FS_PUBLIC_KEY", "./priv/certs/trusted_service.crt"},
  private_key: {:system, "FS_PRIVATE_KEY", "./priv/certs/trusted_service.key"}

config :jwk_provider, JwkProvider.Vault,
  url: {:system, "VAULT_URL", "https://localhost:8200"},
  ca_fingerprint: {:system, "VAULT_CA_FINGERPRINT"},
  token: {:system, "VAULT_TOKEN", "myroot"},
  pki_path: {:system, "VAULT_PKI_PATH", "jwt_ca"},
  pki_role: {:system, "VAULT_PKI_ROLE", "trusted_service"},
  common_name: {:system, "VAULT_PKI_CN", "trusted_service"},
  expire_margin: {:system, "VAULT_EXPIRE_MARGIN", 60}
