defmodule Oauth2Provider.HTTP.AppRoutes do
  use Oauth2Provider.HTTP.Routes,
    auth: true,
    module: Oauth2Provider.HTTP.AppController,
    routes: [
      {:post, "", :create},
      {:get, "/verify", :verify}
    ]
end
