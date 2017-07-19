import HTTP
import JWT
import Authentication

let verifiedJWTKey = "jwt-provider:verified-jwt"

extension Request {
    /// Parses and returns a JWT from the request
    /// if one exists.
    /// The JWT will also be verified with the supplied
    /// signer.
    public func jwt(verifyUsing signer: Signer, and claims: [Claim] = []) throws -> JWT {

        let jwt = try self.parseJWT()

        // verify the signature
        try jwt.verifySignature(using: signer)

        // verify the claims
        try jwt.verifyClaims(claims)
        
        // cache the verified jwt
        verifiedJWT = jwt

        return jwt
    }

    func parseJWT() throws -> JWT {
        // Try to get the authorization header
        guard let authHeader = auth.header else {
            throw AuthenticationError.noAuthorizationHeader
        }

        // Try to retrieve the bearer token
        guard let bearer = authHeader.bearer else {
            throw AuthenticationError.invalidBearerAuthorization
        }

        // Parse the bearer string into a JWT
        return try JWT(token: bearer.string)
    }

    public var verifiedJWT: JWT? {
        get { return storage[verifiedJWTKey] as? JWT }
        set { storage[verifiedJWTKey] = newValue }
    }
    
    public func assertVerifiedJWT() throws -> JWT {
        guard let jwt = verifiedJWT else {
            throw JWTProviderError.noVerifiedJWT
        }
        
        return jwt
    }
}
