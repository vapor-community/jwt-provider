import XCTest
@testable import JWTProviderTests

XCTMain([
     testCase(ProviderTests.allTests),
     testCase(JWTSignerFactoryTests.allTests),
     testCase(JSONWebKeySignerFactoryTests.allTests),
     testCase(PayloadAuthenticationMiddlewareTests.allTests)
])
