defmodule Oauth2Provider.HTTP.Routes do
  defmacro __using__(opts) do
    auth? = Keyword.get(opts, :auth, false)
    routes = Keyword.get(opts, :routes, [])

    quote bind_quoted: [auth?: auth?, routes: routes, opts: opts] do
      use Plug.Router
      import Plug.Conn
      require Logger

      plug(:match)
      plug(:fetch_session)

      if auth? do
        plug(Oauth2Provider.Guardian.Pipeline)
      end

      plug(:dispatch)

      Enum.each(routes, fn {m, r, f} ->
        match(r,
          via: m,
          do:
            apply(unquote(Keyword.get(opts, :module, __MODULE__)), unquote(f), [
              var!(conn),
              var!(conn).params
            ])
        )
      end)

      match(_, do: send_resp(var!(conn), 404, "Not Found"))
    end
  end
end
