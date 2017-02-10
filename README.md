# JWT Provider for Vapor

Adds JWT support to the Vapor web framework.

## Add the dependency to Package.swift

```JSON
.Package(url: "https://github.com/vapor/jwt-provider.git", ...)
```

## Add the provider to your Droplet instance

```swift
import Vapor
import VaporJWT

let drop = Droplet()
try drop.addProvider(VaporJWT.Provider.self)
```

## Config

To build, the first place you'll want to look is the Config/ directory. In their, you should create a secrets folder and a nested `jwt.json`.

```
Config/
  - jwt.json
    secrets/
      - jwt.json
```

The secrets folder is under the gitignore and shouldn't be committed.

Here's an example `secrets/jwt.json`

```json
{
    "signer": {
        "type": "rsa",
        "key": "...",
        "algorithm": "rs256"
    }
}

```

## JWT

For just JWT support, check out [vapor/jwt](https://github.com/vapor/jwt).
