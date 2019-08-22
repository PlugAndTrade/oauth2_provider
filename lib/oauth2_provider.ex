defmodule Oauth2Provider do
  @moduledoc """
  Documentation for Oauth2Provider.
  """

  use Application
  require Logger

  def start(_type, _args) do
    ets_session_table = Elixir.Confex.get_env(:oauth2_provider, :session) |> Keyword.get(:table)
    :ets.new(ets_session_table, [:named_table, :public, read_concurrency: true])

    children = [
      {JwkProvider, [name: JwkProvider]},
      {Oauth2Provider.Repo, []},
      {Oauth2Provider.Token.Registry, [name: :token_registry]}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Oauth2Provider.Supervisor)
  end
end
