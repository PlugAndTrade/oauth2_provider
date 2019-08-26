defmodule Oauth2Provider.AppActor do
  @behaviour Oauth2Provider.Authenticatable

  @type t :: %__MODULE__{
          id: String.t(),
          app: Oauth2.App.t(),
          client: Oauth2.Client.t(),
          user: map()
        }

  defstruct [:id, :app, :client, :user]

  def new(%{id: id} = app, client, user) do
    %__MODULE__{id: id, app: app, client: client, user: user}
  end

  # TODO user_id and claims["sub"] should match
  def find_by_id(id, resource_claims) do
    with {:ok, %{user_id: _user_id, client_id: client_id} = app} <-
           Oauth2Provider.Repo.fetch(Oauth2Provider.App, id),
         {:ok, client} <- Oauth2Provider.Repo.fetch(Oauth2Provider.Client, client_id),
         {:ok, resource} <- Oauth2Provider.Authenticatable.find_by_claims(resource_claims) do
      {:ok, new(app, client, resource)}
    else
      err -> err
    end
  end

  @impl Oauth2Provider.Authenticatable
  def find_by_claims(%{"sub" => id, "resource" => claims}),
    do: find_by_id(id, claims)

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(%{
        "grant_type" => "code",
        "code" => token,
        "client_id" => client_id,
        "client_secret" => client_secret,
        "redirect_uri" => redirect_uri
      } = params) do
    with {:ok, %{app_id: app_id, resource_claims: claims}} <- Oauth2Provider.Token.Registry.pop(:token_registry, token),
         {:ok, %{client: client, app: app} = app_actor} <- find_by_id(app_id, claims),
         :ok <- verify(app, client, client_id, client_secret, redirect_uri) do
      {:ok, app_actor, Map.drop(params, ["grant_type", "code", "client_id", "client_secret", "redirect_uri"])}
    else
      err -> err
    end
  end

  @impl Oauth2Provider.Authenticatable
  def find_and_verify(_),
    do: {:error, %{message: "Authentication failed", code: "ERR_UNAUTHORIZED"}}

  defp verify(
         %{client_id: client_id},
         %{id: client_id, secret: client_secret_hash, redirect_uris: redirect_uris},
         client_id,
         client_secret,
         redirect_uri
       ) do
    case {Crypto.verify_password(Base.decode64!(client_secret_hash), client_secret),
          Enum.any?(redirect_uris, &(&1 == redirect_uri))} do
      {:verified, true} -> :ok
      _ -> {:error, %{message: "Authentication failed", code: "ERR_UNAUTHORIZED"}}
    end
  end

  defp verify(_, _, _, _, _),
    do: {:error, %{message: "Authentication failed", code: "ERR_UNAUTHORIZED"}}

  defimpl Oauth2Provider.Authenticatable.TokenResource do
    def claims(%Oauth2Provider.AppActor{
          client: %{id: client_id},
          user: user,
          app: %{scopes: scopes}
        }),
        do: %{
          "clientId" => client_id,
          "resource" => Oauth2Provider.Authenticatable.claims_from_resource(user),
          "scopes" => scopes
        }

    def sub(%Oauth2Provider.AppActor{id: id}), do: {:ok, id}
  end
end
