defmodule PlugHmacAuth.DefaultRequestContextHandler do
  @behaviour PlugHmacAuth.RequestContextHandler

  @impl PlugHmacAuth.RequestContextHandler
  @spec assign_context(conn :: Plug.Conn.t(), access_key_id :: String.t()) :: {:ok} | {:error, atom()}
  def assign_context(conn, access_key_id) do
    Plug.Conn.assign(conn, :x_client_id, access_key_id)
  end
end
