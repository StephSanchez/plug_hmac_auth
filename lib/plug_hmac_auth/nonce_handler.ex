defmodule PlugHmacAuth.NonceHandler do
   @doc "Define the method of how to validate unicity of nonce"
   @callback validate_nonce_key(nonce :: String.t()) :: :ok | {:error, atom()}

   @doc "Define the method of how to store nonce"
   @callback store_nonce_key(nonce :: String.t()) :: :ok | {:error, atom()}
end
