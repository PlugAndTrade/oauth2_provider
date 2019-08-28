# Oauth2Provider

Implements all parts of OAuth 2.0 and OpenID Connect 1.0.

## TODO

### Refresh token

Given a refresh token the user and client must be identifiable, either throught
saving user claims to database or encoding user claims in the token.

The client must authenticate, if not configured otherwise, when refreshing a
token.

A method for revoking refresh tokens must be provided, since they have very
long ttl.

### Change subject

Provide a method to act on behalf of another subject.

## Installation

The package can be installed by adding `oauth2_provider` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:oauth2_provider, github: "PlugAndTrade/oauth2_provider"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/oauth2_provider](https://hexdocs.pm/oauth2_provider).

## Configuration

### JWK

See [jwk_provider](https://github.com/PlugAndTrade/jwk_provider) for
instruction on how to setup and configure jwks.
