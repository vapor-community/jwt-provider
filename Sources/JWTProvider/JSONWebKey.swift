//
//  JSONWebKey.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 06/06/2017.
//
//

import Foundation
import JSON
import JWT

public struct JSONWebKey {

    public let alg: String

    public let kid: String

    public let kty: String

    public let x5c: [String]?

    public let n: String?

    public let e: String?

    public init(
        alg: String,
        kid: String,
        kty: String,
        x5c: [String]? = nil,
        n: String? = nil,
        e: String? = nil
        ) {

        self.alg = alg
        self.kid = kid
        self.kty = kty
        self.x5c = x5c
        self.n = n
        self.e = e
    }

    private func buildKey() -> Bytes {

        return []
    }

    public func makeSigner() throws -> Signer {

        switch self.kty.lowercased() {
        case "rsa":
            switch self.alg.lowercased() {
            case "rs256":
                return try RS256(key: self.buildKey())
            case "rs384":
                return try RS384(key: self.buildKey())
            case "rs512":
                return try RS512(key: self.buildKey())
            default:
                throw JSONWebKeyError.unsupportedSignerAlgorithm(self.alg)
            }
        default:
            throw JSONWebKeyError.unsupportedSignerType(self.kty)
        }
    }
}

extension JSONWebKey: JSONInitializable {

    public enum JSONKey: String {
        case alg
        case kid
        case kty
        case x5c
        case n
        case e
    }

    public init(json: JSON) throws {

        self.init(
            alg: try json.get(JSONKey.alg.rawValue),
            kid: try json.get(JSONKey.kid.rawValue),
            kty: try json.get(JSONKey.kty.rawValue),
            x5c: try? json.get(JSONKey.x5c.rawValue),
            n: try? json.get(JSONKey.n.rawValue),
            e: try? json.get(JSONKey.e.rawValue)
        )
    }
}

public enum JSONWebKeyError: Swift.Error {
    case missingSigningKey
    case unsupportedSignerType(String)
    case unsupportedSignerAlgorithm(String)
}
