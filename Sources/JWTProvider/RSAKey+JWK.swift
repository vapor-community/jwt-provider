//
//  RSAKey+JWK.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import Foundation
import CTLS
import JWT

public extension RSAKey {

    public init(n: String, e: String, d: String? = nil) throws {

        let nBytes = n.makeBytes().base64URLDecoded
        let eBytes = e.makeBytes().base64URLDecoded


        let rsa = nBytes.withUnsafeBufferPointer({ nRawPointer -> RSAKey in

            return eBytes.withUnsafeBufferPointer({ eRawPointer -> RSAKey in

                if let dBytes = d?.makeBytes().base64URLDecoded {
                    // Private Key
                    return dBytes.withUnsafeBufferPointer({ dRawPointer -> RSAKey in
                        let key = RSA_new()!

                        key.pointee.n = BN_bin2bn(nRawPointer.baseAddress, Int32(nBytes.count), nil)
                        key.pointee.e = BN_bin2bn(eRawPointer.baseAddress, Int32(eBytes.count), nil)
                        key.pointee.d = BN_bin2bn(dRawPointer.baseAddress, Int32(dBytes.count), nil)

                        return .private(key)
                    })
                } else {
                    // Public Key
                    let key = RSA_new()!

                    key.pointee.n = BN_bin2bn(nRawPointer.baseAddress, Int32(nBytes.count), nil)
                    key.pointee.e = BN_bin2bn(eRawPointer.baseAddress, Int32(eBytes.count), nil)

                    return .public(key)
                }
            })
        })

        self = rsa
    }
}
