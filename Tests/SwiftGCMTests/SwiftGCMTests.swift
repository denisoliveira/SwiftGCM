import XCTest
@testable import SwiftGCM

final class SwiftGCMTests: XCTestCase {
    
    func testEncryptation() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        
        let key = Data(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            ])
        
        let nonce = Data(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
            ])
        
        let plaintext = "Test".data(using: .utf8)!
        
        let aad = Data(
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
            ])
        
         let tagSize = 16

        let gcmEnc: SwiftGCM = try! SwiftGCM(key: key, nonce: nonce, tagSize:tagSize)
        let ciphertext: Data = try! gcmEnc.encrypt(auth: aad, plaintext: plaintext)
        
        let gcmDec: SwiftGCM = try! SwiftGCM(key: key, nonce: nonce, tagSize:tagSize)
        let result: Data = try! gcmDec.decrypt(auth: aad, ciphertext: ciphertext)
        
        
        print(String(data: result, encoding: .utf8)!)
        
        XCTAssertEqual(String(data: result, encoding: .utf8), "Test")
    }
    
    func testDecryptation() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        
        let key = Data(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            ])
        
        let nonce = Data(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
            ])
        
        let plaintext = "Test".data(using: .utf8)!
        
        let aad = Data(
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
            ])
        
         let tagSize = 16

        let gcmEnc: SwiftGCM = try! SwiftGCM(key: key, nonce: nonce, tagSize:tagSize)
        let ciphertext: Data = try! gcmEnc.encrypt(auth: aad, plaintext: plaintext)
        
        let gcmDec: SwiftGCM = try! SwiftGCM(key: key, nonce: nonce, tagSize:tagSize)
        let result: Data = try! gcmDec.decrypt(auth: aad, ciphertext: ciphertext)
        
        
        print(String(data: result, encoding: .utf8)!)
        
        XCTAssertEqual(String(data: result, encoding: .utf8), "Test")
    }

    static var allTests = [
        ("testEncryptation", testEncryptation),
        ("testDecryptation", testDecryptation),
    ]
    
}
