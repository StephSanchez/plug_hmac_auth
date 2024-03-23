defmodule PlugHmacAuth.Util do
  require Logger

  def log(opts, message) do
    logger = Keyword.get(opts, :log, false)
    if logger, do: Logger.debug(message)
  end

end
