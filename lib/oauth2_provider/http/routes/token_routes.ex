defmodule Oauth2Provider.HTTP.TokenRoutes do
  use Oauth2Provider.HTTP.Routes,
    auth: false,
    module: Oauth2Provider.HTTP.TokenController,
    routes: [
      {:get, "", :login},
      {:post, ":type", :create}
    ]
end
