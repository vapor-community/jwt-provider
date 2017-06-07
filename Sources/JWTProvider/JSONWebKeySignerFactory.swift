//
//  JSONWebKeySignerFactory.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import Foundation
import JWT
import JSON

public struct JSONWebKeySignerFactory: SignerFactory {

    private enum JSONKey: String {
        case alg
        case kid
        case kty
        case x5c
        case n
        case e
    }

    public let jwk: JSON

    public init(jwk: JSON) {
        self.jwk = jwk
    }

    public func makeSigner() throws -> Signer {

        let kty = (try jwk.get(JSONKey.kty.rawValue) as String).lowercased()

        let alg = (try jwk.get(JSONKey.alg.rawValue) as String).lowercased()

        switch kty {
        case "rsa":

            guard let key: String = try jwk.get(JSONKey.x5c.rawValue) else {
                throw JSONWebKeySignerFactoryError.missingSigningKey
            }

            let bytes = key.makeBytes().base64Decoded

            switch alg {
            case "rs256":
                return try RS256(key: bytes)
            case "rs384":
                return try RS384(key: bytes)
            case "rs512":
                return try RS512(key: bytes)
            default:
                throw JSONWebKeySignerFactoryError.unsupportedSignerAlgorithm(alg)
            }
        default:
            throw JSONWebKeySignerFactoryError.unsupportedSignerType(kty)
        }
    }
}

public enum JSONWebKeySignerFactoryError: Swift.Error {
    case missingSigningKey
    case unsupportedSignerType(String)
    case unsupportedSignerAlgorithm(String)
}
