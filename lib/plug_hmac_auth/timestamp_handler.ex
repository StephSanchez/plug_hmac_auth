defmodule PlugHmacAuth.TimestampHandler do
   @doc "Define the method of how to get `secret_key` by `access_key_id`"
   @callback validate_timestamp_key(timestamp :: Integer) :: :ok | {:error, atom()}
end
