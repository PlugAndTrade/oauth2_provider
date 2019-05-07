defmodule Oauth2Provider.Token do
  @default_ttl 60 * 5

  defstruct id: nil, exp: nil, app_id: nil

  def new(opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @default_ttl)
    id = Keyword.get(opts, :id, UUID.uuid4())
    {:ok, app_id} = Keyword.fetch(opts, :app_id)

    %__MODULE__{
      id: id,
      app_id: app_id,
      exp: :os.system_time(:seconds) + ttl
    }
  end

  def expired?(%__MODULE__{exp: exp}), do: exp < :os.system_time(:seconds)
end
