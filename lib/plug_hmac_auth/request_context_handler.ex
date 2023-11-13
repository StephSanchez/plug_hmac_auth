defmodule PlugHmacAuth.RequestContextHandler do
  @doc "Define the method of how to store information contexte in the request life cycle by `access_key_id`"
  @callback assign_context(conn :: Plug.Conn.t(), access_key_id :: String.t()) :: {:ok} | {:error, atom()}
end
