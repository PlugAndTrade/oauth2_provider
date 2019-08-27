defmodule Oauth2Provider.HTTP.ClientController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug

  def create(conn, params) do
    with :ok <- verify_admin(conn),
         create_params <- validate_create(params),
         {secret, secret_hash} <- generate_secret(),
         changeset <-
           Oauth2Provider.Client.changeset(Map.merge(create_params, %{secret: secret_hash})),
         {:ok, client} <- Oauth2Provider.Repo.insert(changeset) do
      data = client
             |> Map.from_struct()
             |> Map.take([:id, :name, :redirect_uris])
             |> Map.merge(%{secret: secret})
      conn
      |> put_no_cache_headers()
      |> json(201, data)
    else
      {:error, err} ->
        json(conn, 400, %{errors: [err]})

      :forbidden ->
        json(conn, 403, %{errors: [%{
          code: "ERR_NOT_ADMIN",
          message: "Only administrators may create new clients"}]
        })

      err ->
        Logger.error(inspect(err))
        json(conn, 500, %{errors: [%{
          code: "ERR_INTENAL_ERROR",
          message: "Unknown error"
        }]})
    end
  end

  def verify_admin(conn) do
    case current_resource(conn) |> Oauth2Provider.Authenticatable.is_admin?() do
      true -> :ok
      false -> :forbidden
    end
  end

  def generate_secret() do
    secret = :crypto.strong_rand_bytes(24) |> Base.url_encode64()
    secret_hash = Crypto.create_hash(secret) |> Base.encode64()
    {secret, secret_hash}
  end

  def validate_create(%{"name" => name, "redirect_uris" => redirect_uris}) do
    %{name: name, redirect_uris: redirect_uris}
  end
end
