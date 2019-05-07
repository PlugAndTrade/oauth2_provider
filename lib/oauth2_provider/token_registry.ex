defmodule Oauth2Provider.Token.Registry do
  use GenServer

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, opts)
  end

  def init(_opts), do: {:ok, %{}}

  @doc """
  Adds the token to the state and schdules a cleanup for when
  the token is considered expired
  """
  def put(pid, %Oauth2Provider.Token{} = token), do: GenServer.cast(pid, {:put, token})

  @doc """
  Retrieve all tokens issued currently in the store
  """
  def retrieve_all(pid), do: GenServer.call(pid, :retrieve_all)

  @doc """
  Retrieve a token based on id. This process removes the token from the store
  """
  def pop(pid, id), do: GenServer.call(pid, {:pop, id})

  def handle_call({:pop, id}, _from, state) do
    {res, new_state} =
      case Map.pop(state, id) do
        {nil, new_state} ->
          {{:error, %{code: "ERR_TOKEN_INVALID", message: "Invalid token"}}, new_state}

        {value, new_state} ->
          {{:ok, value}, new_state}
      end

    {:reply, res, new_state}
  end

  def handle_call(:retrieve_all, _from, state), do: {:reply, Map.values(state), state}

  def handle_cast({:put, %Oauth2Provider.Token{id: id, exp: exp} = token}, state) do
    schedule_cleanup(id, exp - :os.system_time(:seconds))
    {:noreply, Map.put(state, id, token)}
  end

  def handle_info({:cleanup, id}, state), do: {:noreply, Map.drop(state, [id])}

  defp schedule_cleanup(id, time) do
    Process.send_after(self(), {:cleanup, id}, time * 1000)
  end
end
