//
//  JSONWebKeySignerFactoryTests.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import XCTest
import JSON
import Vapor
import CTLS
import Crypto
@testable import JWTProvider

class JSONWebKeySignerFactoryTests: XCTestCase {

    static let allTests = [
        ("testMakeRS256Signer", testMakeRS256Signer)
    ]

    func testMakeRS256Signer() throws {

/*
        let d = "PP5EBOLYAMa3E-2GNEoOu2M1c174dyy3g1kMroWiG5qQAqDTrP2cy-q_r8cI0XvD6rHbvanD1qmJg1l0dgaVuPAgZeqf5ei2NNEumZf1-Oak5KK0_VxnkmRLyNmz1SGBN80sWexLpQL9ZHU4CH655RGx3bXcmW1k6Nljs--H6t5pF5amhDW8eUKxj1hF8Nqti8EMRVCVRcAzMSzaeexiZbTArTyEXVsl43-NB6Ihqhw4kkxBz8lI_mfT3f9eyEFZn__Pb9dPxZYslQZwz427hm1of5OLqW-ElUMw9KhEmkdes_PRdsgOZQ3WpO2CWilFf5fh1j-NnfqGkgaMpJyr4Q".makeBytes().base64Decoded

        let n = "z9CG1hMY182Hsc3MyMHtQOGFI2vJuj_kh-tzgPSur0oWIrHQMP6ZhvYUV-BHczKiDrCycRE6hpKx5p6CLrO_vMmEYsslr2G65J13FirFAymWjlJnoBY2QiTyxdG4WuRjaNc8gRtKiO6jFP8dZVvTENttAbaXXjAu7lfEcjwg4PYbdN9o_OvJtT0Dh98mbQdmvlZZJ6iQnfynnWTwl4AtIHoUJ3Mbd5QcN3qEFKpL4frHUPnk6eNu7ZvsqkXv6p1lPmPfOLjHgrJfW3Q4z9K6yPV3zkgSZX0e9axKdU7sGFutXzDdQq1uFOMN1IA4ZJnGrTSiYH2YrslV9VRWN7c1VQ".makeBytes().base64Decoded

        d.withUnsafeBufferPointer { p in
            p.
        }

        var base = rawKeyPointer.baseAddress
        let count = rawKey.count

        if let cPrivateKey = d2i_RSAPrivateKey(nil, &base, count)
*/
        let privateJWK = try JSON(bytes: "{\"kty\":\"RSA\",\"d\":\"PP5EBOLYAMa3E-2GNEoOu2M1c174dyy3g1kMroWiG5qQAqDTrP2cy-q_r8cI0XvD6rHbvanD1qmJg1l0dgaVuPAgZeqf5ei2NNEumZf1-Oak5KK0_VxnkmRLyNmz1SGBN80sWexLpQL9ZHU4CH655RGx3bXcmW1k6Nljs--H6t5pF5amhDW8eUKxj1hF8Nqti8EMRVCVRcAzMSzaeexiZbTArTyEXVsl43-NB6Ihqhw4kkxBz8lI_mfT3f9eyEFZn__Pb9dPxZYslQZwz427hm1of5OLqW-ElUMw9KhEmkdes_PRdsgOZQ3WpO2CWilFf5fh1j-NnfqGkgaMpJyr4Q\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"1234\",\"alg\":\"RS256\",\"n\":\"z9CG1hMY182Hsc3MyMHtQOGFI2vJuj_kh-tzgPSur0oWIrHQMP6ZhvYUV-BHczKiDrCycRE6hpKx5p6CLrO_vMmEYsslr2G65J13FirFAymWjlJnoBY2QiTyxdG4WuRjaNc8gRtKiO6jFP8dZVvTENttAbaXXjAu7lfEcjwg4PYbdN9o_OvJtT0Dh98mbQdmvlZZJ6iQnfynnWTwl4AtIHoUJ3Mbd5QcN3qEFKpL4frHUPnk6eNu7ZvsqkXv6p1lPmPfOLjHgrJfW3Q4z9K6yPV3zkgSZX0e9axKdU7sGFutXzDdQq1uFOMN1IA4ZJnGrTSiYH2YrslV9VRWN7c1VQ\"}")

        let privateSigner = try JSONWebKeySignerFactory(jwk: privateJWK).makeSigner()


        let signature = try privateSigner.sign(message: "test")

        try privateSigner.verify(signature: signature, message: "test".makeBytes())
//        try publicSigner.verify(signature: signature, message: "test".makeBytes())
    }
}
