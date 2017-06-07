//
//  SignerFactory.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import Foundation
import JWT

public protocol SignerFactory {

    func makeSigner() throws -> Signer
}
