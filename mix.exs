defmodule Exmime.Mixfile do
  use Mix.Project

  def project do
    [app: :exmime,
     version: "0.1.0",
     elixir: "~> 1.4",
     elixirc_paths: elixirc_paths(Mix.env),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     dialyzer: [
       plt_add_deps: :apps_direct,
       ignore_warnings: "dialyzer.ignore-warnings",
       plt_add_apps: [
         :compiler, :elixir, :kernel, :logger, :stdlib,
         :public_key, :pkcs7]],
     deps: deps()]
  end

  defp elixirc_paths(:test), do: ["lib","test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [
      applications: [:logger,:crypto]
    ]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:dialyxir, "~> 0.5", only: [:dev], runtime: false},
      {:pkcs7, "~> 1.0.2"}
    ]
  end
end
