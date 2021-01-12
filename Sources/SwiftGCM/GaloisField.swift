//
//  GaloisField.swift
//  
//
//  Created by Luke Park.
//  Updated by Denis Oliveira.
//


import Foundation

/// The Field GF(2^128)
internal final class GaloisField {
    private static let r = UInt128(a: 0xE100000000000000, b: 0)
    private static let blockSize: Int = 16
    
    // GHASH. One-time calculation
    static func ghash(x startx: UInt128 = 0, h: UInt128, aad: Data, ciphertext: Data) -> UInt128 {
        var x = calculateX(aad: Array(aad), x: startx, h: h, blockSize: blockSize)
        x = calculateX(ciphertext: Array(ciphertext), x: x, h: h, blockSize: blockSize)
        
        // len(aad) || len(ciphertext)
        let len = UInt128(a: UInt64(aad.count * 8), b: UInt64(ciphertext.count * 8))
        x = multiply((x ^ len), h)
        return x
    }
    
    
    // If data is not a multiple of block size bytes long then the remainder is zero padded
    // Note: It's similar to ZeroPadding, but it's not the same.
    static private func addPadding(_ bytes: Array<UInt8>, blockSize: Int) -> Array<UInt8> {
        if bytes.isEmpty {
            return Array<UInt8>(repeating: 0, count: blockSize)
        }
        
        let remainder = bytes.count % blockSize
        if remainder == 0 {
            return bytes
        }
        
        let paddingCount = blockSize - remainder
        if paddingCount > 0 {
            return bytes + Array<UInt8>(repeating: 0, count: paddingCount)
        }
        return bytes
    }
    
    
    // Calculate Ciphertext part, for all blocks
    // Not used with incremental calculation.
    private static func calculateX(ciphertext: [UInt8], x startx: UInt128, h: UInt128, blockSize: Int) -> UInt128 {
        let pciphertext = addPadding(ciphertext, blockSize: blockSize)
        let blocksCount = pciphertext.count / blockSize
        
        var x = startx
        for i in 0..<blocksCount {
            let cpos = i * blockSize
            let block = pciphertext[pciphertext.startIndex.advanced(by: cpos)..<pciphertext.startIndex.advanced(by: cpos + blockSize)]
            x = calculateX(block: Array(block), x: x, h: h, blockSize: blockSize)
        }
        return x
    }
    
    // block is expected to be padded with addPadding
    private static func calculateX(block ciphertextBlock: Array<UInt8>, x: UInt128, h: UInt128, blockSize: Int) -> UInt128 {
        let k = x ^ UInt128(ciphertextBlock)
        return multiply(k, h)
    }
    
    // Calculate AAD part, for all blocks
    private static func calculateX(aad: [UInt8], x startx: UInt128, h: UInt128, blockSize: Int) -> UInt128 {
        let paad = addPadding(aad, blockSize: blockSize)
        let blocksCount = paad.count / blockSize
        
        var x = startx
        for i in 0..<blocksCount {
            let apos = i * blockSize
            let k = x ^ UInt128(paad[paad.startIndex.advanced(by: apos)..<paad.startIndex.advanced(by: apos + blockSize)])
            x = multiply(k, h)
        }
        
        return x
    }
    
    // Multiplication GF(2^128).
    private static func multiply(_ x: UInt128, _ y: UInt128) -> UInt128 {
        var z: UInt128 = 0
        var v = x
        var k = UInt128(a: 1 << 63, b: 0)
        
        for _ in 0..<128 {
            if y & k == k {
                z = z ^ v
            }
            
            v = v & 1 != 1
                ? v >> 1
                : (v >> 1) ^ r
            
            k = k >> 1
        }
        
        return z
    }
    
    // Padding.
    public static func padToBlockSize(_ x: Data) -> Data {
        let count: Int = blockSize - x.count % blockSize
        var result: Data = Data()
        
        result.append(x)
        for _ in 1...count {
            result.append(0)
        }
        
        return result
    }
    
}
