//
//  PZipTests.swift
//  PZipTests
//
//  Created by Dan Watson on 7/2/20.
//  Copyright © 2020 Dan Watson. All rights reserved.
//

import XCTest

class PZipTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testWriter() throws {
        let key = Password("pzip")
        let plaintext = String(repeating: "Hello, world!", count: 1000).data(using: .utf8)!

        let output = OutputStream.toMemory()
        output.open()

        let writer = PZipWriter(.Stream(stream: output), key: key, compression: .GZIP)
        writer.write(plaintext)
        writer.finalize()
        let data = output.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        print(data.hexEncodedString())

        let input = InputStream(data: data)
        input.open()

        let reader = PZipReader(.Stream(stream: input), keyMaterial: key.material)
        let check = reader.readToEnd()

        XCTAssertEqual(plaintext, check)
    }

    func testReader() throws {
        // Test data from https://imsweb.github.io/pzip/format/
        let data = "B69E0101010200030220074D651516E68F0561B55B81376F9E38C60F0CDAEABE1CBEFCAC0C414C4541A2FD0400030D40010C53FBD24BF5D4283816135FCF8000001DBF3EC0ACFC989B11099F4A40E3AD5DA75862F9A2B17A915C79D2E6C4B2000000000000000D".hexDecodedData()!
        let stream = InputStream(data: data)
        stream.open()

        let reader = PZipReader(.Stream(stream: stream), keyMaterial: "pzip".data(using: .utf8)!)
        let plaintext = reader.readToEnd()

        XCTAssertEqual(plaintext, "Hello, world!".data(using: .utf8))
    }
}
