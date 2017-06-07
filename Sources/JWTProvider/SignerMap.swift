//
//  SignerMap.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import Foundation
import JWT

/// Key: kid, Value: signer
public typealias SignerMap = [String: Signer]

public extension Dictionary where Key == String, Value == Signer {

    /**
     Parses a JSON Web Key Set `jwks.json` config file to create a SignerMap
     */
    public init(jwks: JSON) throws {

        guard let keys = jwks["keys"]?.array else {
            throw SignerMapError.missingKey("keys")
        }

        var map = [String: Signer]()

        for key in keys {

            guard let kid: String = try key.get("kid") else {
                continue
            }

            guard let signer = try? JSONWebKeySignerFactory(jwk: key).makeSigner() else {
                continue
            }

            map[kid] = signer
        }

        self = map
    }

    /**
     Parses a `jwt.json` config file to create a SignerMap
     */
    public init(jwt: JSON) throws {

        guard let signerConfig = jwt["signer"]?.object else {
            throw SignerMapError.missingKey("signer")
        }

        guard let kid: String = signerConfig["kid"]?.string else {
            throw SignerMapError.missingKey("kid")
        }

        let signer = try JWTSignerFactory(jwt: jwt).makeSigner()

        self = [kid: signer]
    }
}

public enum SignerMapError: Swift.Error {
    case missingKey(String)
}
