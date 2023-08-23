defmodule Ueberauth.Strategy.Goonfleet.OAuth do
  @moduledoc """
  An implementation of OAuth2 for Goonfleet SSO

  To add your `client_id` and `client_secret` include these values in your configuration.

      config :ueberauth, Ueberauth.Strategy.Goonfleet.OAuth,
        client_id: System.get_env("GOONFLEET_CLIENT_ID"),
        client_secret: System.get_env("GOONFLEET_SECRET_KEY")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://esi.goonfleet.com",
    authorize_url: "https://esi.goonfleet.com/oauth/authorize",
    token_url: "https://esi.goonfleet.com/oauth/token"
  ]

  @doc """
  Construct a client for requests to Goonfleet.
  This will be setup automatically for you in `Ueberauth.Strategy.Goonfleet`.
  These options are only useful for usage outside the normal callback phase
  of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Goonfleet.OAuth)

    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    json_library = Ueberauth.json_library()

    OAuth2.Client.new(opts)
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    client([token: token])
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_token!(params \\ [], opts \\ []) do
    client =
      opts
      |> client
      |> OAuth2.Client.get_token!(params)

    client.token
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  # need to remove the extra authorization params or else ESI will complain about multiple credentials
  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
    |> delete_param(:client_secret)
    |> delete_param(:client_id)
  end

  defp delete_param(%{params: params} = client, key) do
    %{client | params: Map.delete(params, "#{key}")}
  end
end
