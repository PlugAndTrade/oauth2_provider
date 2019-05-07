defmodule Oauth2Provider.HTTP.UserRoutes do
  use Oauth2Provider.HTTP.Routes,
    auth: true,
    module: Oauth2Provider.HTTP.UserController,
    routes: [
      {:get, "/me", :get}
    ]
end
