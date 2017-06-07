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
        case d
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

            let key: RSAKey

            if let n: String = try jwk.get(JSONKey.n.rawValue), let e: String = try jwk.get(JSONKey.e.rawValue) {
                key = try RSAKey(n: n, e: e, d: try? jwk.get(JSONKey.d.rawValue))
            } else {
                throw JSONWebKeySignerFactoryError.missingSigningKey
            }

            switch alg {
            case "rs256":
                return RS256(rsaKey: key)
            case "rs384":
                return RS384(rsaKey: key)
            case "rs512":
                return RS512(rsaKey: key)
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
