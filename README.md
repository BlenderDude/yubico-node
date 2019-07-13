# Typescript (Javascript) Yubico API Implementation

This is a JS implementation of the Yubico Validation Protocol as outlined in their [documentation](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html). All of the extra security precautions are implemented such as using the client secret to hash the request on its way out, and validate the response on its way in. This library is also incredibly small and has no outside dependencies.

## Features

-   Managed request hashing and response verification
-   Typescript types built in
-   Environment Variable Defaults

## Environment Variables

```

YUBICO_CLIENT_ID    = Client ID from Yubico
YUBICO_SECRET       = Secret from Yubico
YUBICO_SL           = The SL to use (0 - 100, fast, or secure)
YUBICO_TIMEOUT      = The timeout for the request (number)
YUBICO_API_SERVERS  = If you run your own compliant verification servers, place the hosts  in a comma separated list (ex. api.yubico.com,api2.yubico.com, etc.)

```

## Yubico

#### `constructor(options?: IYubicoConstructor)`

The `options` parameter contains all of the options you might want to set for the verification requests. Some parameters are requrired,
but having an environment variable suffices for the requirement. The `options` parameter is not required at all of all parameters are met with environment variables.

| option       | required | type                             | default            | example        |
| ------------ | -------- | -------------------------------- | ------------------ | -------------- |
| `clientId`   | ✅       | `string`                         | N/A                | `"MyClientID"` |
| `secret`     | ✅       | `string`                         | N/A                | `"MySecret"`   |
| `sl`         |          | `number (0-100),"fast","secure"` | none               | `"secure"`     |
| `timeout`    |          | `number`                         | none               | `"secure"`     |
| `apiServers` |          | `string[]`                       | Yubico API Servers | `"secure"`     |

#### `verify(otp: string): Promise<Response>`

Verify the OTP against the verification servers. This will return a [Response](#Response) class that can be picked apart to get the data you need.

## Response

#### `getOneTimePassword(): string`

Returns the same OTP that was passed into the `verify` function.

#### `getTimestampUTC(): Date`

Returns the UTC timestamp that was given in response from the verification server.

#### `getTimestamp(): Date`

Returns the timestamp from when the key was pressed.

#### `getSessionCounter(): number`

Returns the internal usage counter provided by the key from when it was pressed.

#### `getSessionUse(): number`

Returns the internal session usage counter provided by the key from when it was pressed.

#### `getStatus(): ResponseStatus`

Returns the response status of the request. This should always be `ResponseStatus.OK` as all other responses will throw an error.

#### `getPublicId(): string`

Returns the public ID of the key. This is unique to each key, but is encoded in [ModHex](https://developers.yubico.com/OTP/Modhex_Converter.html).
If you need the public ID as a number (aka. the serial number), use `getSerialNumber()`.

#### `getSerialNumber():number`

Returns the serial number of the key. This is decoded from [ModHex](https://developers.yubico.com/OTP/Modhex_Converter.html) and represented as a `UIntBE`.
