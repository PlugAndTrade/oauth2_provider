defmodule Oauth2Provider.HTTP.AppController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug
  require EEx

  @authorize_form_path Elixir.Confex.get_env(:oauth2_provider, :html)
                       |> Keyword.get(:authorize_form)

  EEx.function_from_file(:def, :render_authorize_form, @authorize_form_path, [
    :authorize_url,
    :verify_url,
    :client_id,
    :scopes
  ])

  def create(conn, params) do
    res =
      %{error?: false, errors: []}
      |> validate_create_params(params)
      |> get_resource(conn)
      |> get_client()
      |> create_changeset()
      |> insert_app()

    case res do
      %{error?: false, errors: [], app: %{}, params: %{verify_url: redirect_to}} ->
        conn
        |> put_resp_header("location", "#{redirect_to}")
        |> send_resp(302, "")

      %{error?: false, errors: [], app: %{} = app} ->
        conn |> json(201, app)

      %{changeset: nil, errors: errors} ->
        json(conn, 400, %{errors: errors})

      %{params: nil, errors: errors} ->
        json(conn, 400, %{errors: errors})

      %{client: nil, errors: errors} ->
        json(conn, 404, %{errors: errors})

      %{error?: true, errors: errors} ->
        json(conn, 500, %{errors: errors})
    end
  end

  def verify(conn, params) do
    res =
      %{error?: false, errors: []}
      |> validate_verify_params(params)
      |> get_resource(conn)
      |> get_client()
      |> verify_redirect_uri()
      |> get_app()
      |> verify_scopes()
      |> generate_token()

    case res do
      %{
        redirect_uri_valid?: true,
        scopes_valid?: true,
        params: %{redirect_uri: redirect_uri, state: state},
        token: %{id: token}
      } ->
        conn
        |> put_resp_header(
          "location",
          add_query_params(redirect_uri, %{"authorization_code" => token, "state" => state})
        )
        |> send_resp(302, "")

      %{redirect_uri_valid?: false, errors: errors} ->
        conn |> json(400, %{errors: errors})

      %{params: nil, errors: errors} ->
        conn |> json(400, %{errors: errors})

      %{scopes_valid?: false, errors: errors} ->
        conn |> json(400, %{errors: errors})

      %{client: nil, errors: errors} ->
        conn |> json(404, %{errors: errors})

      %{app: nil, params: %{client_id: client_id, scopes: scopes}, error?: false} ->
        conn
        |> put_resp_content_type("text/html; charset=utf8")
        |> send_resp(
          200,
          render_authorize_form(
            "#{Confex.fetch_env!(:oauth2_provider, :path_prefix)}/apps",
            request_url(conn),
            client_id,
            scopes
          )
        )

      %{error?: true, errors: errors} ->
        Logger.error(inspect(res))
        conn |> json(500, %{errors: errors})
    end
  end

  defp append_error(state, err),
    do:
      state
      |> Map.update!(:errors, &[err | &1])
      |> Map.put(:error?, true)

  defp generate_token(%{app: %{id: app_id}, resource: resource_claims} = state) do
    token = Oauth2Provider.Token.new(app_id: app_id, resource_claims: resource_claims)
    Oauth2Provider.Token.Registry.put(:token_registry, token)
    Map.put(state, :token, token)
  end

  defp generate_token(state), do: state

  defp verify_redirect_uri(
         %{client: %{redirect_uris: redirect_uris}, params: %{redirect_uri: redirect_uri}} = state
       ) do
    if Enum.any?(redirect_uris, &(&1 == redirect_uri)),
      do: Map.put(state, :redirect_uri_valid?, true),
      else:
        state
        |> append_error(%{message: "Uri does not match", code: "ERR_INVALID_URI"})
        |> Map.put(:redirect_uri_valid?, false)
  end

  defp verify_redirect_uri(state), do: state

  defp validate_verify_params(res, %{
         "client_id" => client_id,
         "scope" => scopes,
         "state" => state,
         "response_type" => "code",
         "redirect_uri" => redirect_uri
       }) do
    Map.put(res, :params, %{
      client_id: client_id,
      scopes: String.split(scopes, " "),
      state: state,
      redirect_uri: redirect_uri
    })
  end

  defp validate_verify_params(state, _params) do
    state
    |> append_error(%{message: "Invalid parametes", code: "ERR_BAD_REQUEST"})
    |> Map.put(:params, nil)
  end

  defp get_resource(state, conn) do
    case current_resource(conn) do
      nil -> append_error(state, %{message: "Not logged in", code: "ERR_UNAUTHORIZED"})
      resource -> Map.put(state, :resource, Oauth2Provider.Authenticatable.claims_from_resource(resource, "access"))
    end
  end

  defp get_app(%{params: %{client_id: client_id}, resource: %{"sub" => sub}, error?: false} = state) do
    Map.put(
      state,
      :app,
      Oauth2Provider.Repo.get_by(Oauth2Provider.App, client_id: client_id, user_id: sub)
    )
  end

  defp get_app(state), do: state

  defp verify_scopes(
         %{params: %{scopes: request_scopes}, app: %{scopes: authorized_scopes}} = state
       ) do
    if "openid" in request_scopes and Enum.all?(request_scopes, fn s -> Enum.any?(authorized_scopes, &(&1 == s)) end) do
      Map.put(state, :scopes_valid?, true)
    else
      state
      |> append_error(%{message: "Scopes does not match", code: "ERR_INVALID_SCOPES"})
      |> Map.put(:scopes_valid?, false)
    end
  end

  defp verify_scopes(state), do: state

  defp create_changeset(
         %{
           params: %{scopes: scopes},
           resource: %{"sub" => sub},
           client: %{id: client_id, name: client_name}
         } = state
       ) do
    case Oauth2Provider.App.changeset(%{
           user_id: sub,
           client_id: client_id,
           name: client_name,
           scopes: scopes
         }) do
      %{valid?: false, errors: errs} ->
        state
        |> append_error(%{message: "Invalid changeset: #{inspect(errs)}", code: "ERR_BAD_REQUEST"})
        |> Map.put(:changeset, nil)

      app ->
        Map.put(state, :changeset, app)
    end
  end

  defp create_changeset(state), do: state

  defp insert_app(%{error?: false, changeset: changeset} = state) do
    case Oauth2Provider.Repo.insert(changeset) do
      {:ok, app} ->
        Map.put(state, :app, EctoHelper.strip_meta(app))

      {:error, %{valid?: false, errors: errors}} ->
        errors
        |> Enum.map(&%{message: "Invalid changeset: #{inspect(&1)}", code: "ERR_BAD_REQUEST"})
        |> Enum.reduce(state, &append_error/2)
        |> Map.put(:app, nil)
    end
  end

  defp insert_app(state), do: state

  defp get_client(%{params: %{client_id: client_id}} = state) do
    case Oauth2Provider.Repo.get(Oauth2Provider.Client, client_id) do
      nil ->
        state
        |> append_error(%{message: "Client not found", code: "ERR_NOT_FOUND"})
        |> Map.put(:client, nil)

      client ->
        Map.put(state, :client, client)
    end
  end

  defp get_client(state), do: state

  defp validate_create_params(state, %{"client_id" => _, "scopes" => scopes} = params) do
    params =
      params
      |> Map.take(["client_id", "scopes", "verify_url"])
      |> Enum.reduce(%{}, fn {k, v}, p -> Map.put(p, String.to_existing_atom(k), v) end)

    if "openid" in scopes do
      Map.put(state, :params, params)
    else
      state
      |> append_error(%{message: "Invalid parametes", code: "ERR_BAD_REQUEST"})
      |> Map.put(:params, nil)
    end

  end

  defp validate_create_params(state, _) do
    state
    |> append_error(%{message: "Invalid parametes", code: "ERR_BAD_REQUEST"})
    |> Map.put(:params, nil)
  end
end
