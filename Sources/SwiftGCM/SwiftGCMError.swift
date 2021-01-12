//
//  SwiftGCMError.swift
//
//
//  Created by Luke Park.
//  Updated by Denis Oliveira.
//


import Foundation

public enum SwiftGCMError: Error {
    case invalidKeySize
    case invalidDataSize
    case invalidTagSize
    case instanceAlreadyUsed
    case commonCryptoError(err: Int32)
    case authTagValidation
}
