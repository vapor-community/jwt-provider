//
//  KeyIDClaim.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import JWT
import Node

public struct KeyIDHeader: Header {
    public static let name = "kid"
    public let node: Node

    init(identifier: String) {
        node = .string(identifier)
    }
}

public extension JWT {

    public var keyIdentifier: String? {
        return self.headers[KeyIDHeader.name]?.string
    }
}
