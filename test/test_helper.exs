Oauth2Provider.TestRepo.start_link()
JwkProvider.start_link([
  name: JwkProvider,
  provider: :fs,
  fs: [
    public_key: "./priv/certs/trusted_service.crt",
    private_key: "./priv/certs/trusted_service.key"
  ]
])
ExUnit.start()
