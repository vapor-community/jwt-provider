import Foundation
import JWT

public protocol SignerFactory {

    func makeSigner() throws -> Signer
}
