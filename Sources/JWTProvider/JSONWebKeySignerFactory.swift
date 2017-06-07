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

            let key: Bytes

            if let n: String = try jwk.get(JSONKey.n.rawValue), let d: String = try jwk.get(JSONKey.d.rawValue) {
                // Private key
                key = n.makeBytes().base64Decoded + d.makeBytes().base64Decoded
            } else if let n: String = try jwk.get(JSONKey.n.rawValue), let e: String = try jwk.get(JSONKey.e.rawValue) {
                // Public key with modulus and exponent
                key = n.makeBytes()
            } else if let x5c: String = try jwk.get(JSONKey.x5c.rawValue) {
                // Public key with x5c
                key = x5c.makeBytes()
            } else {
                throw JSONWebKeySignerFactoryError.missingSigningKey
            }

            switch alg {
            case "rs256":
                return try RS256(key: key.hexEncoded)
            case "rs384":
                return try RS384(key: key)
            case "rs512":
                return try RS512(key: key)
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
