//
//  UInt128.swift
//
//
//  Created by Luke Park.
//  Updated by Denis Oliveira.
//


import Foundation

internal struct UInt128: Equatable, ExpressibleByIntegerLiteral {
    let i: (a: UInt64, b: UInt64)
    
    typealias IntegerLiteralType = UInt64
    
    init(integerLiteral value: IntegerLiteralType) {
        self = UInt128(value)
    }
    
    init(_ raw: Array<UInt8>) {
        self = raw.prefix(MemoryLayout<UInt128>.stride).withUnsafeBytes({ (rawBufferPointer) -> UInt128 in
            let arr = rawBufferPointer.bindMemory(to: UInt64.self)
            return UInt128((arr[0].bigEndian, arr[1].bigEndian))
        })
    }
    
    init(_ raw: Data) {
        self.init(Array(raw))
    }
    
    init(_ raw: ArraySlice<UInt8>) {
        self.init(Array(raw))
    }
    
    init(_ i: (a: UInt64, b: UInt64)) {
        self.i = i
    }
    
    init(a: UInt64, b: UInt64) {
        self.init((a, b))
    }
    
    init(_ b: UInt64) {
        self.init((0, b))
    }
    
    // Data
    var data: Data {
        var at = i.a.bigEndian
        var bt = i.b.bigEndian
        
        let ar = Data(bytes: &at, count: MemoryLayout.size(ofValue: at))
        let br = Data(bytes: &bt, count: MemoryLayout.size(ofValue: bt))
        
        var result = Data()
        result.append(ar)
        result.append(br)
        return result
    }
    
    
    // Successive counter values are generated using the function incr(), which treats the rightmost 32
    // bits of its argument as a nonnegative integer with the least significant bit on the right
    func increment() -> UInt128 {
        let b = self.i.b + 1
        let a = (b == 0 ? self.i.a + 1 : self.i.a)
        return UInt128((a, b))
    }
    
    
    static func ^(n1: UInt128, n2: UInt128) -> UInt128 {
        return UInt128((n1.i.a ^ n2.i.a, n1.i.b ^ n2.i.b))
    }
    
    static func &(n1: UInt128, n2: UInt128) -> UInt128 {
        return UInt128((n1.i.a & n2.i.a, n1.i.b & n2.i.b))
    }
    
    static func >>(value: UInt128, by: Int) -> UInt128 {
        var result = value
        for _ in 0..<by {
            let a = result.i.a >> 1
            let b = result.i.b >> 1 + ((result.i.a & 1) << 63)
            result = UInt128((a, b))
        }
        return result
    }
    
    // Equatable.
    static func ==(lhs: UInt128, rhs: UInt128) -> Bool {
        return lhs.i == rhs.i
    }
    
    static func !=(lhs: UInt128, rhs: UInt128) -> Bool {
        return !(lhs == rhs)
    }
}
