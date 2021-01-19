//
//  SwiftGCM.swift
//
//
//  Created by Luke Park.
//  Updated by Denis Oliveira.
//


import Foundation
import CommonCrypto

public class SwiftGCM {
    
    private static let keySize128: Int = 16
    private static let keySize192: Int = 24
    private static let keySize256: Int = 32
    
    public static let tagSize128: Int = 16
    public static let tagSize120: Int = 15
    public static let tagSize112: Int = 14
    public static let tagSize104: Int = 13
    public static let tagSize96: Int = 12
    public static let tagSize64: Int = 8
    public static let tagSize32: Int = 4
    
    private static let standardNonceSize: Int = 12
    private static let blockSize: Int = 16
    
    private static let initialCounterSuffix: Data = Data([0, 0, 0, 1])
    private static let emptyBlock: Data = Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    
    private let key: Data
    private let tagSize: Int
    private var counter: UInt128
    
    private var h: UInt128
    private var used: Bool
    
    // Constructor.
    public init(key: Data, nonce: Data, tagSize: Int) throws {
        if tagSize != SwiftGCM.tagSize128 && tagSize != SwiftGCM.tagSize120 && tagSize != SwiftGCM.tagSize112 && tagSize != SwiftGCM.tagSize104 && tagSize != SwiftGCM.tagSize96 && tagSize != SwiftGCM.tagSize64 && tagSize != SwiftGCM.tagSize32 {
            throw SwiftGCMError.invalidTagSize
        }
        
        if key.count != SwiftGCM.keySize128 && key.count != SwiftGCM.keySize192 && key.count != SwiftGCM.keySize256 {
            throw SwiftGCMError.invalidKeySize
        }
        
        self.key = key
        self.tagSize = tagSize
        
        self.h = UInt128(0)
        self.h = try UInt128((SwiftGCM.encryptBlock(key: key, data: SwiftGCM.emptyBlock)))
        
        if nonce.count != SwiftGCM.standardNonceSize {
            self.counter = GaloisField.ghash(h: h, aad: Data(), ciphertext: nonce)
        } else {
            self.counter = SwiftGCM.makeCounter(nonce: nonce)
        }
        
        self.used = false
    }
    
    // Encrypt/Decrypt.
    public func encrypt(auth: Data?, plaintext: Data) throws -> Data {
        if used { throw SwiftGCMError.instanceAlreadyUsed }
        
        let dataPadded: Data = GaloisField.padToBlockSize(plaintext)
        let blockCount: Int = dataPadded.count / SwiftGCM.blockSize
        let h: Data = try SwiftGCM.encryptBlock(key: key, data: SwiftGCM.emptyBlock)
        let eky0: Data = try SwiftGCM.encryptBlock(key: key, data: counter.data)
        let authData: Data = (auth != nil ? auth! : Data())
        var ct: Data = Data()
        
        for i in 0..<blockCount {
            counter = counter.increment()
            let ekyi: Data = try SwiftGCM.encryptBlock(key: key, data: counter.data)
            
            let ptBlock: Data = dataPadded[dataPadded.startIndex + i * SwiftGCM.blockSize..<dataPadded.startIndex + i * SwiftGCM.blockSize + SwiftGCM.blockSize]
            ct.append(SwiftGCM.xorData(lhs: ptBlock, rhs: ekyi))
        }
        
        ct = ct[ct.startIndex..<ct.startIndex + plaintext.count]
        let ghash = GaloisField.ghash(h: UInt128(h), aad: authData, ciphertext: ct)
        var t = (ghash ^ UInt128(eky0)).data
        t = t[t.startIndex..<tagSize]
        
        var result: Data = Data()
        
        result.append(ct)
        result.append(t)
        
        used = true
        return result
    }
    
    public func decrypt(auth: Data?, ciphertext: Data) throws -> Data {
        if used { throw SwiftGCMError.instanceAlreadyUsed }
        
        let ct: Data = ciphertext[ciphertext.startIndex..<ciphertext.startIndex + ciphertext.count - SwiftGCM.blockSize]
        let givenT: Data = ciphertext[(ciphertext.startIndex + ciphertext.count - SwiftGCM.blockSize)...]
        
        let h: Data = try SwiftGCM.encryptBlock(key: key, data: SwiftGCM.emptyBlock)
        let eky0: Data = try SwiftGCM.encryptBlock(key: key, data: counter.data)
        let authData: Data = (auth != nil ? auth! : Data())
        let ghash = GaloisField.ghash(h: UInt128(h), aad: authData, ciphertext: ct)
        var computedT = (ghash ^ UInt128(eky0)).data
        computedT = computedT[computedT.startIndex..<tagSize]
        
        if !SwiftGCM.tsCompare(lhs: computedT, rhs: givenT) {
            throw SwiftGCMError.authTagValidation
        }
        
        let dataPadded: Data = GaloisField.padToBlockSize(ct)
        let blockCount: Int = dataPadded.count / SwiftGCM.blockSize
        
        var pt: Data = Data()
        
        for i in 0..<blockCount {
            counter = counter.increment()
            let ekyi: Data = try SwiftGCM.encryptBlock(key: key, data: counter.data)
            let ctBlock: Data = dataPadded[dataPadded.startIndex + i * SwiftGCM.blockSize..<dataPadded.startIndex + i * SwiftGCM.blockSize + SwiftGCM.blockSize]
            pt.append(SwiftGCM.xorData(lhs: ctBlock, rhs: ekyi))
        }
        
        pt = pt[0..<ct.count]
        
        used = true
        return pt
    }
    
    private static func encryptBlock(key: Data, data: Data) throws -> Data {
        if data.count != SwiftGCM.blockSize {
            throw SwiftGCMError.invalidDataSize
        }
        
        var dataMutable: Data = data
        var keyMutable: Data = key
        
        var dataOut: Data = Data(count: data.count)
        var dataOutMoved: size_t = 0
        
        let keyLength = key.count
        let dataInLength = data.count
        let dataOutAvailable = dataOut.count
        
        let status = dataOut.withUnsafeMutableBytes { dataOutRaw in
            dataMutable.withUnsafeMutableBytes { dataInRaw in
                keyMutable.withUnsafeMutableBytes{ keyRaw in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyRaw.baseAddress, keyLength,
                        nil,
                        dataInRaw.baseAddress, dataInLength,
                        dataOutRaw.baseAddress, dataOutAvailable, &dataOutMoved
                    )
                }
            }
        }
        
        if status != kCCSuccess {
            throw SwiftGCMError.commonCryptoError(err: status)
        }
        
        return dataOut
    }
    
    // Counter.
    private static func makeCounter(nonce: Data) -> UInt128 {
        var result = Data()
        result.append(nonce)
        result.append(SwiftGCM.initialCounterSuffix)
        return UInt128(result)
    }
    
    // Misc.
    private static func xorData(lhs: Data, rhs: Data) -> Data {
        var result: Data = Data(capacity: lhs.count)
        zip([UInt8](lhs), [UInt8](rhs)).forEach {
            result.append($0 ^ $1)
        }
        return result
    }
    
    private static func tsCompare(lhs: Data, rhs: Data) -> Bool {
        if lhs.count != rhs.count { return false }
        let result = zip([UInt8](lhs), [UInt8](rhs)).reduce(0) { (partial, element) -> UInt8 in
            partial | element.0 ^ element.1
        }
        return result == 0
    }
    
}
