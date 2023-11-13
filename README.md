# HMAC Authentication Plug

![Elixir CI](https://github.com/StephSanchez/plug_hmac_auth/workflows/Elixir%20CI/badge.svg)
[![Hex.pm](https://img.shields.io/hexpm/v/plug_hmac_auth.svg)](https://hex.pm/packages/plug_hmac_auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)

[Plug](https://hex.pm/packages/plug) support for [HMAC](https://en.wikipedia.org/wiki/HMAC) authentication. This is used for authentication between server sides.

![plug_hmac_auth](https://user-images.githubusercontent.com/13026209/82148208-180c1380-987d-11ea-9087-96b9110c0675.png)

## Installation

This package can be installed by adding `plug_hmac_auth` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:plug_hmac_auth, "~> 0.1.0"}
  ]
end
```

## Usage

### HTTP GET SAMPLE (readable request)
This sample is provided using Javascript
```js
const uuid = require('uuid');
const cryptoJS = require("crypto-js");
const moment = require("moment");

const nonce = uuid.v4();
const client_id = 'USE YOUR CLIENT ID';
const host = "localhsot";
const method = "GET";
const epoch = moment().unix();
const path = request.url.getPath();
// payload format
// host: ${host}; method: ${method}; request_path /sample/sample/id; query_string ; nonce: holaf6; timestamp: 1693860698
var payload = `host: ${host}; method: ${method}; request_path: ${path}; query_string ; nonce: ${nonce}; timestamp: ${epoch}`;
console.log(payload);

// Accordind to your configuration :hmac_hash_algo
var authorize = cryptoJS.HmacSHA512(payload, 'USE YOUR PRIVATE KEY').toString(cryptoJS.enc.Base64);

headers.add([{
    key: "Authorization",
    value: authorize
},{
    key: "X-Authorization-Id",
    value: client_id
},{
    key: "X-Authorization-Nonce",
    value: nonce
},{
    key: "X-Authorization-Timestamp",
    value: epoch
}]);

```

### HTTP POST SAMPLE (writable request)
this sample is provided usins javascript

```js
const uuid = require('uuid');
const cryptoJS = require("crypto-js");
const moment = require("moment");

const nonce = uuid.v4();
const client_id = 'USE YOUR CLIENT ID';
const host = "localhost"
const method = "POST";

const epoch = moment().unix();
const body_hash = CryptoJS.MD5(request.body.toString()).toString()
const path = request.url.getPath();
// payload format
// host: localhost; method: POST; request_path: /sample/sample; body_hash: f6ec8fd8d77bf5e19f6a28a37353d6ef; nonce: holaf7; timestamp: 1694248700
var payload = `host: ${host}; method: ${method}; request_path: ${path}; body_hash: ${body_hash}; nonce: ${nonce}; timestamp: ${epoch}`;

// Accordind to your configuration :hmac_hash_algo
var authorize = cryptoJS.HmacSHA512(payload, 'USE YOUR PRIVATE KEY').toString(cryptoJS.enc.Base64);

headers.add([{
    key: "Authorization",
    value: authorize
},{
    key: "X-Authorization-Id",
    value: client_id
},{
    key: "X-Authorization-Nonce",
    value: nonce
},{
    key: "X-Authorization-Timestamp",
    value: epoch
}]);

```

### PlugHmacAuthExampleWeb.Endpoint

We use some raw data as [payload](https://github.com/flipay/plug_hmac_auth/blob/a978ac5051686ce1a9539a315a062009fd2045ae/lib/plug_hmac_auth.ex#L76) to verify the request from client.

For those `GET` requests, we use `query string` as payload. 

For other requests, we use `raw body` as payload. But the raw body of request can only be read once. That means we can't read the raw body after the `Plug.Parsers`. Instead of the original body reader provided by `Plug.Parsers`, we need to use a custom body reader to cache the `raw body`.

```elixir
plug Plug.Parsers,
  parsers: [:urlencoded, :multipart, :json],
  pass: ["*/*"],
  json_decoder: Phoenix.json_library(),
  body_reader: {PlugHmacAuth.BodyReader, :read_body, []}
```

### PlugHmacAuthExampleWeb.Router

In the router module of your web site, define a new pipeline to enable the plug of HMAC authentication:

```elixir
pipeline :plug_hmac_auth do
    plug(PlugHmacAuth,
      key_access_id: "X-Authorization-Id",
      key_signature: "Authorization",
      key_nonce: "X-Authorization-Nonce",
      key_timestamp: "X-Authorization-Timestamp",
      hmac_hash_algo: :sha512,
      secret_handler: SampleApp.Handlers.SecretHandler,
      error_handler: SampleApp.Handlers.AuthErrorHandlers,
      nonce_handler: SampleApp.Handlers.NonceHandler,
      timestamp_handler: SampleApp.Handlers.TimestampHandler
      request_context_handler: SampleApp.Handlers.RequestContextHandler
    )
  end
```

Module `PlugHmacAuth` needs these options:

- `key_access_id`: The key of `access_id` in the HTTP request header.
- `key_signature`: The key of `signature` in the HTTP request header.
- `key_nonce`: The key of `nonce` in the HTTP request header. The nonce global attribute is a content attribute defining a cryptographic nonce ("number used once") which can be used by Content Security Policy to determine whether or not a given fetch will be allowed to proceed for a given element.
- `key_timestamps`: The Key `timestamps` in the HTTP request header. The timestamp global attribute  includes information about the time when the HTTP request was sent. It helps in managing cache mechanisms, handling resource updates, and ensuring synchronization between the client and server.
- `hmac_hash_algo`: The algorithm of HMAC.
- `secret_handler`: Secret handler is the module to get the `secret` by given `access_id`.
- `error_handler`: Error handler is the module to handle the unauthorized request.
- `nonce_handler` : Nonce handler to determine unicity of a request
- `timestamp_handler` : Timestamps handler to determine the validity of a request
- `request_context_handler` : Request Context handler to offer the possiblity to add a user context within the request context.


### HMAC hash algorithm

[Here](https://github.com/flipay/plug_hmac_auth/blob/a978ac5051686ce1a9539a315a062009fd2045ae/lib/plug_hmac_auth.ex#L12) lists the algorithms current supported.

### Secret Handler

We need to implement the callback function of `get_secret_key/1` to let authenticator know how to get the secret key by given access id.

### Error Handler

We need to implement the callback function of `auth_error/2` to let the authenticator know how to handle the unauthorized request.

### Nonce handler

We need to implement the callback function of `validate_nonce_key/1` to let the authenticator know how to handle the request unicity. We need to implement the callback function of `store_nonce_key` to let the authenticator know how to store the nonce. The nonce is store only if the payload verification match.

### Timestamp Handler

We need to implement the callback function of `validate_timestamp_key/1` to let the authenticator know how to handle the request validity. the timestamp is a Unix Timestamp.

### Request Context handler

We need to implement the callback function of `assign_context/2` to let the authenticator know how to handle the request contexte. the first parameter is the `%Plug.Conn{}`. The second one is the `access_id` of the request.
#### Nota
The authenticator add directly the `access_id` in the connection assigns with key `x_client_id`

## Documentation

See [HexDocs](https://hexdocs.pm/plug_hmac_auth).

## Reference

- [Demo API Server Using This HMAC Authentication Plug](https://github.com/flipay/plug_hmac_auth_example)
- [HMAC Authentication: Better protection for your API](https://dev.to/pim/hmac-authentication-better-protection-for-your-api-4e0)
