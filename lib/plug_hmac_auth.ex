defmodule PlugHmacAuth do
  @moduledoc """
  `PlugHmacAuth` provides a `Plug` for `HMAC authentication`.
  """
  require Logger

  @behaviour Plug
  import Plug.Conn

  @type opts :: [
          key_access_id: String.t(),
          key_signature: String.t(),
          key_nonce: String.t(),
          key_timestamp: integer(),
          hmac_hash_algo:
            :md4
            | :md5
            | :sha
            | :sha224
            | :sha256
            | :sha384
            | :sha3_224
            | :sha3_256
            | :sha3_384
            | :sha3_512
            | :sha512,
          secret_handler: module(),
          error_handler: module()
        ]

  @spec init(opts :: Keyword.t()) :: Keyword.t()
  def init(opts) do
    opts
  end

  @spec call(Plug.Conn.t(), Keyword.t()) :: Plug.Conn.t()
  def call(conn, opts) do

    key_access_id = Keyword.get(opts, :key_access_id, "no-key-access-id") |> String.downcase()
    key_signature = Keyword.get(opts, :key_signature, "no-key-signature") |> String.downcase()
    key_nonce = Keyword.get(opts, :key_nonce, "no-key-nonce") |> String.downcase()
    key_timestamp = Keyword.get(opts, :key_timestamp, "no-key-timestamp") |> String.downcase()
    hmac_hash_algo = Keyword.get(opts, :hmac_hash_algo, :no_hash_algo)
    secret_handler = Keyword.get(opts, :secret_handler, :no_secret_handler)
    error_handler = Keyword.get(opts, :error_handler, :no_error_handler)
    nonce_handler = Keyword.get(opts, :nonce_handler, :no_nonce_handler)
    timestamp_handler = Keyword.get(opts, :timestamp_handler, :no_timestamp_handler)
    request_context_handler = Keyword.get(opts, :request_context_handler, :no_request_context_handler)

    Logger.debug("key_access_id : #{key_access_id}")
    Logger.debug("key_signature : #{key_signature}")
    Logger.debug("key_nonce : #{key_nonce}")
    Logger.debug("key_timestamp : #{key_timestamp}")
    Logger.debug("hmac_hash_algo : #{hmac_hash_algo}")

    with {:ok, access_key} <- fetch_token_from_header(conn, key_access_id),
         {:ok, access_signature} <- fetch_token_from_header(conn, key_signature),
         {:ok, access_nonce} <- fetch_token_from_header(conn, key_nonce),
         {:ok, access_timestamp} <- fetch_token_from_header(conn, key_timestamp),
         {:ok, secret_key} <- secret_handler.get_secret_key(access_key),
         {request_timestamp, _base} <- Integer.parse(access_timestamp),
         :ok <- nonce_handler.validate_nonce_key(access_nonce),
         :ok <- timestamp_handler.validate_timestamp_key(request_timestamp),
         :ok <- verify_payload(conn, secret_key, access_signature,access_nonce, request_timestamp, hmac_hash_algo) do
          nonce_handler.store_nonce_key(access_nonce)
          conn
          |> request_context_handler.assign_context(access_key)
          |> put_resp_header("x-access-nonce", access_nonce)
    else
      {:error, code} ->
        Logger.error("Invalid code : #{code}")
        conn |> error_handler.auth_error(code) |> halt()
    end
  end

  @spec verify_payload(
          Plug.Conn.t(),
          String.t(),
          String.t(),
          String.t(),
          integer(),
          :md4
          | :md5
          | :sha
          | :sha224
          | :sha256
          | :sha384
          | :sha3_224
          | :sha3_256
          | :sha3_384
          | :sha3_512
          | :sha512
        ) :: :ok | {:error, :invalid_signature}
  def verify_payload(conn, secret_key, access_signature, access_nonce, access_timestamps, hmac_hash_algo)

  def verify_payload(conn, secret_key, access_signature, access_nonce, access_timestamps, hmac_hash_algo) do
    payload=conn |> get_payload() |> concat_payload("nonce", access_nonce)|> concat_payload("timestamp", access_timestamps)
    verif = payload |> gen_signature(secret_key, hmac_hash_algo)
    Logger.debug(["access_signature:", inspect(access_signature)])
    Logger.debug(["verif           : ",inspect(verif)])
    Logger.debug(["payload         : ",inspect(payload)])

    if verif == access_signature do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  @spec get_payload(Plug.Conn.t()) :: String.t()
  def get_payload(%Plug.Conn{method: "GET", query_string: query_string, host: host, request_path: request_path}) do
    expected =  "host: #{host}; method: GET; request_path: #{request_path}; query_string #{Base.encode64(query_string)}"
    Logger.debug("Expected payload : #{expected}")
    expected
  end
  def get_payload(%Plug.Conn{method: method, host: host, request_path: request_path} = conn) do
    body_hash = conn.private[:md5sum]
    Logger.debug("Final resquest body md5sum : #{body_hash}")
    expected = "host: #{host}; method: #{method}; request_path: #{request_path}; body_hash: #{body_hash}"
    Logger.debug("Expected payload : #{expected}")
    expected
  end

  @spec concat_payload(String.t(), String.t(), String.t()) :: String.t()
  def concat_payload(current, key, value), do: current <> "; #{key}: #{value}"

  @doc """
  Returns signatre generated by payload and secret key.
  """
  @spec gen_signature(String.t(), String.t(), atom()) :: String.t()
  def gen_signature(payload, secret_key, hmac_hash_algo),
    do: :crypto.mac(:hmac, hmac_hash_algo, secret_key, payload) |> Base.encode64()

  @doc """
  Returns the first token from http request header by specific key.
  """
  @spec fetch_token_from_header(Plug.Conn.t(), binary()) ::
          {:error, :invalid_key} | {:ok, binary()}
  def fetch_token_from_header(conn, key)

  def fetch_token_from_header(conn, key) when is_binary(key) do
    case get_req_header(conn, key) do
      [] -> {:error, :invalid_key}
      [token | _] -> {:ok, String.trim(token)}
    end
  end

  def fetch_token_from_header(_conn, key) when not is_binary(key) do
    {:error, :invalid_key}
  end
end
