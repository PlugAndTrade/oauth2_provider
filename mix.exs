defmodule Oauth2Provider.MixProject do
  use Mix.Project

  def project do
    [
      app: :oauth2_provider,
      version: "0.1.0",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: compiler_paths(Mix.env())
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :eex],
      mod: {Oauth2Provider, []}
    ]
  end

  defp compiler_paths(:test), do: ["test/helpers", "test/impl"] ++ compiler_paths(:prod)
  defp compiler_paths(:dev), do: ["test/helpers", "test/impl"] ++ compiler_paths(:prod)
  defp compiler_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:confex, "~> 3.4.0"},
      {:ecto_sql, "~> 3.1"},
      {:guardian, "~> 1.2"},
      {:jason, "~> 1.0"},
      {:postgrex, "~> 0.15.0"},
      {:plug, "~> 1.7"},
      {:plug_cowboy, "~> 2.0"},
      {:plug_crypto, "~> 1.0"},
      {:uuid, "~> 1.1"}
    ]
  end
end
