defmodule Oauth2Provider.HTTP.ClientRoutes do
  use Oauth2Provider.HTTP.Routes,
    auth: true,
    module: Oauth2Provider.HTTP.ClientController,
    routes: [
      {:post, "", :create},
      {:get, "", :list}
    ]
end
