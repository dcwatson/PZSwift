//
//  main.swift
//  PZSwift
//
//  Created by Dan Watson on 7/2/20.
//  Copyright © 2020 Dan Watson. All rights reserved.
//

import ArgumentParser
import Foundation

struct PZipCLI: ParsableCommand {
    @Flag(help: "Automatically generate an encryption password.")
    var auto = false

    @Flag(help: "Keep the original file.")
    var keep = false

    @Option(help: "Password to use when encrypting or decrypting.")
    var password: String?

    @Argument(help: "The file to encrypt or decrypt.")
    var file: String

    mutating func run() throws {
        var key: Password!
        if let password = password {
            key = Password(password)
        } else if auto {
            let pw = Data(randomOfLength: 15)!.hexEncodedString(upper: false)
            key = Password(pw)
            print("Automatically generated password:", pw)
        } else {
            throw ValidationError("A password is required.")
        }
        if let infile = FileHandle(forReadingAtPath: file) {
            if file.hasSuffix(".pz") {
                let outpath = String(file.prefix(file.count - 3))
                if FileManager.default.createFile(atPath: outpath, contents: nil, attributes: nil) {
                    if let outfile = FileHandle(forWritingAtPath: outpath) {
                        ParallelDecryptor(.File(file: infile), dest: .File(file: outfile), key: key.material).decrypt()
                    }
                }
            } else {
                let outpath = file.appending(".pz")
                if FileManager.default.createFile(atPath: outpath, contents: nil, attributes: nil) {
                    if let outfile = FileHandle(forWritingAtPath: outpath) {
                        ParallelEncryptor(.File(file: infile), dest: .File(file: outfile), key: key, compression: .GZIP).encrypt()
                    }
                }
            }
        }
    }
}

PZipCLI.main()
