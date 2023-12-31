# Überauth Goonfleet SSO

Goonfleet OAuth2 strategy for Überauth

## Installation

1. Setup your application following instructions at the [Goonfleet forums](https://developers.eveonline.com/).

2. Add `:ueberauth_eve_sso` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_github, "~> 0.1}]
    end
    ```

3. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_goonfleet]]
    end
    ```

4. Add Goonfleet provider to your ueberauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        goonfleet: {Ueberauth.Strategy.Goonfleet, []}
      ]
    ```

5. Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.Goonfleet.OAuth,
      client_id: System.get_env("GOONFLEET_CLIENT_ID"),
      client_secret: System.get_env("GOONFLEET_SECRET_KEY")
    ```

    Or, to read the client credentials at runtime:
    ```elixir
    config :ueberauth, Ueberauth.Strategy.Goonfleet.OAuth,
      client_id: {:system, "GOONFLEET_CLIENT_ID"},
      client_secret: {:system, "GOONFLEET_SECRET_KEY"}
    ```

6. Include the Ueberauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller

      pipeline :browser do
        plug Ueberauth
        ...
      end
    end
    ```

7.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
    end
    ```

8. Your controller needs to implement callbacks to deal with `Ueberauth.Auth` and `Ueberauth.Failure` responses.

## Calling

Depending on the configured url you can initiate the request through:

    /auth/goonfleet

Or with options:

    /auth/goonfleet?scope=openid

By default the requested scope is empty (""). This allows access to all public endpoints and identifies the EVE Character.
Scope can be configured either explicitly as a `scope` query value on the request path or in your configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        goonfleet: {Ueberauth.Strategy.Goonfleet, [default_scope: "openid"]}
      ]

The `state` param is required by EVE SSO and should be a nonce generated for each request.

## License

Please see [LICENSE](https://github.com/marcinruszkiewicz/ueberauth_goonfleet/blob/master/LICENSE) for licensing details.

