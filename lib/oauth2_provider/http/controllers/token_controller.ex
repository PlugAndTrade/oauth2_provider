defmodule Oauth2Provider.HTTP.TokenController do
  use Oauth2Provider.HTTP.Controller
  import Oauth2Provider.Guardian.Plug
  require EEx

  @login_form_path Elixir.Confex.get_env(:oauth2_provider, :html) |> Keyword.get(:login_form)

  EEx.function_from_file(:defp, :render_login_form, @login_form_path, [
    :login_url
  ])

  def login(conn, _params) do
    conn
    |> put_resp_content_type("text/html; charset=utf8")
    |> send_resp(200, render_login_form(request_url(conn)))
  end

  def create(conn, params) do
    with {:ok, %{type: type}} <- validate(params),
         {:ok, resource} <- Oauth2Provider.Authenticatable.find_and_verify(type, params) do
      conn =
        sign_in(conn, resource, Oauth2Provider.Authenticatable.claims_from_resource(resource))

      case params do
        %{"redirect_to" => redirect_to} ->
          conn
          |> put_resp_header("location", redirect_to)
          |> send_resp(302, "")

        _ ->
          json(
            conn,
            201,
            %{access_token: current_token(conn)}
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

  defp validate(%{"type" => type}), do: {:ok, %{type: type}}

  defp validate(_),
    do:
      {:error,
       %{
         message: "Invalid credentials",
         code: "ERR_BAD_REQUEST"
       }}
end
