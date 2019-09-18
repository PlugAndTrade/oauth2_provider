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

  def find_by_id(id, %{"sub" => resource_sub} = resource_claims) do
    with {:ok, %{client_id: client_id} = app} <-
           Oauth2Provider.Store.search_one(Oauth2Provider.App, id: id, user_id: resource_sub),
         {:ok, client} <- Oauth2Provider.Store.fetch(Oauth2Provider.Client, client_id),
         {:ok, resource} <- Oauth2Provider.Authenticatable.find_by_claims(resource_claims) do
      {:ok, new(app, client, resource)}
    else
      err -> err
    end
  end

  @impl Oauth2Provider.Authenticatable
  def find_by_claims(%{"client_id" => client_id, "sub" => res_id, "urn:pnt:oauth2:resource_typ" => res_type} = claims) do
    with {:ok, app} <-
           Oauth2Provider.Store.search_one(Oauth2Provider.App, client_id: client_id, user_id: res_id),
         {:ok, client} <-
           Oauth2Provider.Store.fetch(Oauth2Provider.Client, client_id),
         {:ok, resource} <-
           Oauth2Provider.Authenticatable.find_by_claims(Map.put(claims, "urn:pnt:oauth2:sub_typ", res_type)) do
      {:ok, new(app, client, resource)}
    else
      err -> err
    end
  end

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

  @impl Oauth2Provider.Authenticatable
  def is_admin?(_), do: false

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
          user: resource,
          app: %{scopes: scopes}
    }, typ) do
      {:ok, res_type} = Oauth2Provider.Authenticatable.get_type_from_impl(resource)
      resource_claims = Oauth2Provider.Authenticatable.TokenResource.claims(resource, typ)
      app_claims = %{
        "client_id" => client_id,
        "azp" => client_id,
        "scope" => Enum.join(scopes, " "),
        "aud" => [client_id],
        "urn:pnt:oauth2:resource_typ" => res_type
      }
      Oauth2Provider.Authenticatable.merge_claims(resource_claims, app_claims)
    end

    def sub(%Oauth2Provider.AppActor{user: resource}),
      do: Oauth2Provider.Authenticatable.TokenResource.sub(resource)
  end
end
