defmodule UeberauthGoonfleet.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :ueberauth_goonfleet,
      version: @version,
      name: "Ueberauth Goonfleet",
      package: package(),
      elixir: "~> 1.9",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env() == :prod,
      source_url: "https://github.com/marcinruszkiewicz/ueberauth_goonfleet",
      homepage_url: "https://github.com/marcinruszkiewicz/ueberauth_goonfleet",
      description: description(),
      deps: deps(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      applications: [:logger, :ueberauth, :oauth2]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 2.0"},
      {:ueberauth, "~> 0.6"},

      # dev/test only dependencies
      {:credo, "~> 0.8", only: [:dev, :test]},

      # docs dependencies
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp docs do
    [extras: ["README.md"]]
  end

  defp description do
    "An Ueberauth strategy for using the Goonfleet SSO to authenticate your users."
  end

  defp package do
    [files: ["lib", "mix.exs", "README.md", "LICENSE"],
     maintainers: ["Marcin Ruszkiewicz"],
      licenses: ["MIT"],
      links: %{"GitHub": "https://github.com/marcinruszkiewicz/ueberauth_goonfleet"}]
  end
end
