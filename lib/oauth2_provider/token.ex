defmodule Oauth2Provider.Token do
  @default_ttl 60 * 5

  @type t :: %__MODULE__{
          id: String.t(),
          app_id: String.t(),
          exp: pos_integer(),
          resource_claims: map()
        }

  defstruct id: nil, exp: nil, app_id: nil, resource_claims: nil

  def new(opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @default_ttl)
    id = Keyword.get(opts, :id, UUID.uuid4())
    claims = Keyword.get(opts, :resource_claims, %{})
    {:ok, app_id} = Keyword.fetch(opts, :app_id)

    %__MODULE__{
      id: id,
      app_id: app_id,
      exp: :os.system_time(:seconds) + ttl,
      resource_claims: claims
    }
  end

  def expired?(%__MODULE__{exp: exp}), do: exp < :os.system_time(:seconds)
end
