defmodule PlugHmacAuth.BodyReader do
  @moduledoc """
  BodyReader is a `body_reader` for `Plug.Parsers`.
  In addition to the default behavior, it also cache the
  raw body params in `assigns`.
  """
  require Logger

  @spec read_body(Plug.Conn.t(), keyword) :: {:ok, binary, map}
  def read_body(conn, opts) do
    # read the body from the connection
    {:ok, body, conn} = Plug.Conn.read_body(conn, opts)

    # compute our md5 hash
    md5sum = :crypto.hash(:md5, body) |> Base.encode16() |> String.downcase()
    Logger.debug("Initial resquest body md5sum : #{md5sum}")

    # shove the md5sum into a private key on the connection
    conn = Plug.Conn.put_private(conn, :md5sum, md5sum)

    {:ok, body, conn}
  end
end
