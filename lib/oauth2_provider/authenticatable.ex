defmodule Oauth2Provider.Authenticatable do
  @callback find_by_subject(String.t()) :: {:ok, term()}
  @callback find_by_id(String.t()) :: {:ok, term()}
  @callback find_and_verify(map()) :: {:ok, term()}

  @autheticatables Application.get_env(:oauth2_provider, __MODULE__) |> Keyword.fetch!(:modules)

  defprotocol TokenResource do
    @doc "Construct the claims to be encoded in the token from the resource"
    @spec claims(term()) :: map()
    def claims(resource)

    @doc "Returns the value to be used as subject in the token"
    @spec sub(term()) :: {:ok, String.t()} | {:error, %{code: String.t(), message: String.t()}}
    def sub(resource)
  end

  def find_by_id(type, id) do
    case get_impl_from_type(type) do
      {:ok, impl} -> impl.find_by_id(id)
      err -> err
    end
  end

  def find_and_verify(type, params) do
    case get_impl_from_type(type) do
      {:ok, impl} -> impl.find_and_verify(params)
      err -> err
    end
  end

  def claims_from_resource(%impl{} = res) do
    case get_type_from_impl(impl) do
      {:ok, type} ->
        {:ok, sub} = TokenResource.sub(res)
        Map.merge(TokenResource.claims(res), %{"subType" => type, "sub" => sub})
      err -> err
    end
  end

  def get_type_from_impl(impl) do
    case Enum.find_value(@autheticatables, nil, fn {type, mod} -> if mod == impl, do: type, else: nil end) do
      nil -> {:error, %{message: "Unknown resource type", code: "ERR_AUTH_UNKOWN_RESOURCE_TYPE"}}
      type -> {:ok, type}
    end
  end

  def get_impl_from_type(type) do
    case Map.get(@autheticatables, type) do
      nil -> {:error, %{message: "Unknown resource type", code: "ERR_AUTH_UNKOWN_RESOURCE_TYPE"}}
      impl -> {:ok, impl}
    end
  end
end
