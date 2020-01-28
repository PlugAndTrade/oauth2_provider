defmodule Oauth2Provider.Authenticatable do
  @callback is_admin?(map()) :: bool()
  @callback find_by_claims(map()) :: {:ok, term()} | {:error, map()}
  @callback find_and_verify(map()) :: {:ok, term(), term()} | {:error, map()}

  @autheticatables Application.get_env(:oauth2_provider, __MODULE__) |> Keyword.fetch!(:modules)

  defprotocol TokenResource do
    @doc "Construct the claims to be encoded in the token from the resource"
    @spec claims(term(), map()) :: map()
    def claims(resource, typ)

    @doc "Returns the value to be used as subject in the token"
    @spec sub(term()) :: {:ok, String.t()} | {:error, %{code: String.t(), message: String.t()}}
    def sub(resource)
  end

  def find_by_claims(%{"urn:pnt:oauth2:sub_typ" => type} = claims) do
    case get_impl_from_type(type) do
      {:ok, impl} -> impl.find_by_claims(claims)
      err -> err
    end
  end

  def find_and_verify(type, params) do
    case get_impl_from_type(type) do
      {:ok, impl} -> impl.find_and_verify(params)
      err -> err
    end
  end

  def claims_from_resource(%impl{} = res, claims) do
    case get_type_from_impl(impl) do
      {:ok, type} ->
        claims
        |> merge_claims(TokenResource.claims(res, claims))
        |> Map.put("urn:pnt:oauth2:sub_typ", type)

      err ->
        err
    end
  end

  def merge_claims(a, b) do
    Map.merge(a, b, &merge_claim/3)
  end

  def merge_claim("aud", a, b) when is_list(a) and is_list(b),
    do: (a ++ b) |> Enum.uniq()

  def merge_claim("aud", a, b) when is_list(a),
    do: (a ++ [b]) |> Enum.uniq()

  def merge_claim("aud", a, b) when is_list(b),
    do: [a | b] |> Enum.uniq()

  def merge_claim(_key, _a, b),
    do: b

  def is_admin?(%impl{} = res), do: impl.is_admin?(res)

  def get_type_from_impl(%impl{}), do: get_type_from_impl(impl)

  def get_type_from_impl(impl) do
    case Enum.find_value(@autheticatables, nil, fn {type, mod} ->
           if mod == impl, do: type, else: nil
         end) do
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
