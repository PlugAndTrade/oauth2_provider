defmodule Oauth2Provider.HTTP.TokenController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug
  require EEx

  @login_http_response Elixir.Confex.get_env(:oauth2_provider, :init_login, &Oauth2Provider.HTTP.TokenController.login_html_template/2)

  if not is_nil(Elixir.Confex.get_env(:oauth2_provider, :html) |> Keyword.get(:login_form)) do
    @login_form_path Elixir.Confex.get_env(:oauth2_provider, :html) |> Keyword.get(:login_form)

    EEx.function_from_file(:defp, :render_login_form, @login_form_path, [
      :login_url,
      :params
    ])

    def login_html_template(conn, params) do
      conn
      |> put_resp_content_type("text/html; charset=utf8")
      |> send_resp(200, render_login_form(request_url(conn), params))
    end
  end

  def login(conn, params) do
    @login_http_response.(conn, params)
  end

  def create(conn, params) do
    with {:ok, %{type: type}} <- validate(params),
         {:ok, resource, params} <- Oauth2Provider.Authenticatable.find_and_verify(type, params),
         {:ok, access_token, id_token, %{"exp" => exp} = claims} <- Oauth2Provider.Guardian.generate_tokens(resource, %{}) do

      conn = conn
      |> put_current_claims(claims)
      |> put_current_resource(resource)
      |> put_current_token(access_token)
      |> put_session_token(access_token)

      case params do
        %{"redirect_to" => redirect_to} ->
          conn
          |> put_resp_header("location", redirect_to)
          |> send_resp(302, "")

        _ ->
          conn
          |> put_no_cache_headers()
          |> json(
            201,
            %{
              "access_token" => access_token,
              "id_token" => id_token,
              "token_type" => "Bearer",
              "expires_in" => exp - :os.system_time(:seconds),
            }
          )
      end
    else
      {:error, %{code: "ERR_UNAUTHORIZED"} = err} ->
        json(conn, 401, %{errors: [err]})

      {:error, err} ->
        Logger.error(inspect(err))
        json(conn, 400, %{errors: [err]})

      err ->
        Logger.error(inspect(err))

        json(
          conn,
          500,
          %{errors: [%{message: "Unknown error", code: "ERR_UNKNOWN_ERROR"}]}
        )
    end
  end

  def current(conn, _params) do
    case authenticated?(conn) do
      true ->
        %{"exp" => exp} = current_claims(conn)
        ttl = exp - :os.system_time(:seconds)
        conn
        |> put_no_cache_headers()
        |> json(
          200,
          %{
            "access_token" => current_token(conn),
            "token_type" => "Bearer",
            "expires_in" => ttl,
          }
        )
      false ->
        json(
          conn,
          401,
          %{errors: [%{code: "ERR_NOT_AUTHENTICATED", message: "Must be authenticated to retreive token data."}]}
        )
    end
  end

  defp validate(%{"type" => type}), do: {:ok, %{type: type}}

  defp validate(_),
    do:
      {:error,
       %{
         message: "Invalid credentials",
         code: "ERR_BAD_REQUEST"
       }}
end
