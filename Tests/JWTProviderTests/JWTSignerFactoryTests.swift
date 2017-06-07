//
//  JWTSignerFactoryTests.swift
//  JWTProvider
//
//  Created by Valerio Mazzeo on 07/06/2017.
//
//

import XCTest
import JSON
import Vapor
@testable import JWTProvider

class JWTSignerFactoryTests: XCTestCase {

    static let allTests = [
        ("testMakeRS256Signer", testMakeRS256Signer)
    ]

    func testMakeRS256Signer() throws {

        let privateKey = "MIIEpQIBAAKCAQEAq9IyIvhllcz9dTubJair9stTDR/3OQtO87NeWwk/7/Pte13c5s4gQariuX+Q7KMAqjvR4s2Fn3Q7bNLroRkWEV0LpQA/ft056DVO4z3iqcplTGnGR1VHfKAKFquazV8QSgjq4+cD2A0rHCfk1PcAP0fB3Xc52f6yoYzZyW7tJvfd3QamHOu3zAXbpAkpUk0N5fn4bumL4rF4j5jiKcZDspNfhSrhDZpXW7TyWiMmDQLYtSvCj9MK6JW79fTr8WyRrXVmRXBnGFktKrnmkbsQba1GKwVDUCx6E+nm5ZStE8vcwuOy0U1EtrcjiDprM1uGCCvjcOOb40voxXoRN9szdwIDAQABAoIBABOc/d4iDq6H5NLSCAbHd0HHueZApN7dHJkS+41Ww/anGI/BiirKksIMOK9GEYwBm1zTUUUbgspN4U6t0PnlvDAlN+QQ4C6iIC8Sjru/37TUBrYvSNPxtyRRvHUUB6qz1E8vL2jugPDTp/0hzKxGub9/eHDIYFEzEr8ALgghYm7VIpl7WRp+hd028lhokGmeDzU+aoDH3DiNFwARG2Rsjbs4AQU065wHy7lrqP5Cjj9WFE5ycEcSqpup8GCklClJwrPTlj5rVa6QwDFs5tRS3R4c8dBnEtWgxjUeLjnbvZJEIp3tcjekIC0NYQ3NscW9+s1WYF6i0CXucUEYRC6fBMECgYEA1bIBqBx3fNcurAULg4nRCWYTAXAhRYU+N1nD8jzNIobPqMOF73b78DBBQTsbiH9LGSVP2Tt1AzSVMx5Wa5lseeJLGH56Ayah7HtOYYlyzdxrD5pa/0RndklWi0J4xFOcrG3n35dJNpsOjiMcZfoGbs73R1KfZKxhCmyIM283BCECgYEAzdYEzRKRtzfiUpTu56aFo65IgCRyNiFzrkOeaLRFvi4ifsPnpRL14LY8NQIGz58FnG8nRfrZgcExOmydWDVNzpOvR8nZ8zoTjWaHMed5y6dUFBf5lGehKGkRygeUhSLRBPBXJ0ScwEkeMbSv+7rl22VgoHa4Ds816B2xLldvRJcCgYEAs8IWhKzVko2MdCWWRuMylV5pFGeXhVyNNpBrNSUSRj3zBvraetKzIZvl+JJZGdxCdvedEJZkWvrrmuGlPsQDrQ+/re4OgwIHad9b0s6FZUhKQwjMDTkkcytEAsc6waO4ApA9Yidn7ehHOSet5taIfMPa3QNSk6QxyUv80o92TyECgYEAu3c4WC2ZWO0ky2GpVIFtJW4NyednvbUpzoT3ORU2j8ck059I0ic6mLZgj0aRPXbvfVIeyrV0c6CoXTWe+D9T5djLwu4r+kHinN3MM79GRhzXjpVnUaowNMW81euhcMAM7hqWxcTPnrD5NvwBa5sEzZS/NGXrrFE8H3Mrc7FePXECgYEAofgTcuhSGNoiWlwsiBHpXbe75fzG2QxDGBVK6AdL0gTM2hoeTGdsmM7V/0HFkXDViw9wOb4SaWG5wnGLmk3iJEo5DW1gJY6TVXRtzrqfGLK/kui1h+QzrfI7Hvgv6iX5cmA0Wf7oBvXq3HjnaTiquqJdoQQHlzU52kbJX5cLbYo="

        let publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq9IyIvhllcz9dTubJair9stTDR/3OQtO87NeWwk/7/Pte13c5s4gQariuX+Q7KMAqjvR4s2Fn3Q7bNLroRkWEV0LpQA/ft056DVO4z3iqcplTGnGR1VHfKAKFquazV8QSgjq4+cD2A0rHCfk1PcAP0fB3Xc52f6yoYzZyW7tJvfd3QamHOu3zAXbpAkpUk0N5fn4bumL4rF4j5jiKcZDspNfhSrhDZpXW7TyWiMmDQLYtSvCj9MK6JW79fTr8WyRrXVmRXBnGFktKrnmkbsQba1GKwVDUCx6E+nm5ZStE8vcwuOy0U1EtrcjiDprM1uGCCvjcOOb40voxXoRN9szdwIDAQAB"

        let privateSigner = try JWTConfigSignerFactory(signerConfig: Config([
                "type": "rsa",
                "algorithm": "rs256",
                "key": Config(privateKey)
            ])).makeSigner()

        let publicSigner = try JWTConfigSignerFactory(signerConfig: Config([
            "type": "rsa",
            "algorithm": "rs256",
            "key": Config(publicKey)
            ])).makeSigner()

        let signature = try privateSigner.sign(message: "test")

        try privateSigner.verify(signature: signature, message: "test".makeBytes())
        try publicSigner.verify(signature: signature, message: "test".makeBytes())
    }
}
