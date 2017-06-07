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

    public init(n: String, e: String) throws {

        let nBytes = n.makeBytes().base64Decoded
        let eBytes = e.makeBytes().base64Decoded

        guard let rsa = nBytes.withUnsafeBufferPointer({ nRawPointer -> RSAKey? in

            return eBytes.withUnsafeBufferPointer({ eRawPointer -> RSAKey? in

                let key = RSA_new()!

                key.pointee.n = BN_bin2bn(nRawPointer.baseAddress, Int32(nBytes.count), nil)
                key.pointee.e = BN_bin2bn(eRawPointer.baseAddress, Int32(eBytes.count), nil)

                return .public(key)
            })

        }) else {
            throw JWTError.createKey
        }

        self = rsa
    }

    public init(n: String, d: String) throws {

        let nBytes = n.makeBytes().base64Decoded
        let dBytes = d.makeBytes().base64Decoded

        guard let rsa = dBytes.withUnsafeBufferPointer({ dRawPointer -> RSAKey? in

            return nBytes.withUnsafeBufferPointer({ nRawPointer -> RSAKey? in

                let key = RSA_new()!

                key.pointee.n = BN_bin2bn(nRawPointer.baseAddress, Int32(nBytes.count), nil)
                key.pointee.d = BN_bin2bn(dRawPointer.baseAddress, Int32(dBytes.count), nil)

                print(key.pointee)

                return .private(key)
            })
            
        }) else {
            throw JWTError.createKey
        }
        
        self = rsa
    }
}
