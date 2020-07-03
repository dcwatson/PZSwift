//
//  PZip.swift
//  PZip
//
//  Created by Dan Watson on 6/26/20.
//

import CommonCrypto
import CryptoKit
import Foundation
import Gzip
import Security

struct Flags: OptionSet {
    let rawValue: UInt8

    static let AppendLength = Flags(rawValue: 1 << 0)
}

public enum Tag: UInt8 {
    case Nonce = 1
    case Salt = 2
    case Iterations = 253 // -3
    case Info = 4
    case Filename = 5
    case Application = 6
    case MimeType = 7
    case Comment = 127
}

public typealias PZipTags = [Tag: Data]

public enum Algorithm: UInt8, CaseIterable, Identifiable {
    case AES_GCM_256 = 1

    public var id: UInt8 { rawValue }

    func tags() -> [Tag: Data] {
        switch self {
        case .AES_GCM_256:
            return [
                .Nonce: Data(randomOfLength: 12)!,
            ]
        }
    }

    func encrypt(_ data: Data, key: SymmetricKey, tags: PZipTags, counter: Int) throws -> Data {
        switch self {
        case .AES_GCM_256:
            let nonce = tags[.Nonce]!.deriveNonce(counter)
            let box = try AES.GCM.seal(data, using: key, nonce: nonce)
            return box.ciphertext + box.tag
        }
    }

    func decrypt(_ data: Data, key: SymmetricKey, tags: PZipTags, counter: Int) throws -> Data {
        switch self {
        case .AES_GCM_256:
            let nonce = tags[.Nonce]!.deriveNonce(counter)
            let ciphertext = data.prefix(data.count - 16)
            let tag = data.suffix(16)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: key)
        }
    }
}

public enum Compression: UInt8, CaseIterable, Identifiable {
    case None = 0
    case GZIP = 1

    public var id: UInt8 { rawValue }

    func tags() -> PZipTags {
        [:]
    }

    func compress(_ data: Data) throws -> Data {
        switch self {
        case .None:
            return data
        case .GZIP:
            return try data.gzipped()
        }
    }

    func decompress(_ data: Data) throws -> Data {
        switch self {
        case .None:
            return data
        case .GZIP:
            return try data.gunzipped()
        }
    }
}

public enum KeyDerivation: UInt8 {
    case Raw = 0
    case HKDF_SHA256 = 1
    case PBKDF2_SHA256 = 2

    func derive(_ data: Data, tags: PZipTags) -> SymmetricKey {
        switch self {
        case .Raw:
            return SymmetricKey(data: data)
        case .HKDF_SHA256:
            let keyData = hkdf_sha256(data, salt: tags[.Salt] ?? Data(), info: Data())
            return SymmetricKey(data: keyData!)
        case .PBKDF2_SHA256:
            var iterations: UInt32 = 200_000
            if let iterBytes = tags[.Iterations] {
                iterations = iterBytes.readInt()
            }
            let keyData = pbkdf2_sha256(data, salt: tags[.Salt] ?? Data(), iterations: Int(iterations))
            return SymmetricKey(data: keyData!)
        }
    }
}

public struct PZipHeader {
    static let LAST_BLOCK = UInt32(0x8000_0000)

    var version: UInt8
    var flags: Flags
    var algorithm: Algorithm
    var kdf: KeyDerivation
    var compression: Compression
    var tags: PZipTags

    init(version: UInt8 = 1, flags: Flags = [.AppendLength], algorithm: Algorithm = .AES_GCM_256, kdf: KeyDerivation, compression: Compression = .GZIP, tags: PZipTags = [:]) {
        self.version = version
        self.flags = flags
        self.algorithm = algorithm
        self.kdf = kdf
        self.compression = compression
        self.tags = tags
    }

    init(from: PZipSource) {
        let header = from.read(8)
        // TODO: check magic
        version = header[2]
        flags = Flags(rawValue: header[3])
        algorithm = Algorithm(rawValue: header[4])!
        kdf = KeyDerivation(rawValue: header[5])!
        compression = Compression(rawValue: header[6])!
        tags = [:]
        let numTags = header[7]
        for _ in 0 ..< numTags {
            let tagHeader = from.read(2)
            let tag = Tag(rawValue: tagHeader[0])!
            let tagData = from.read(Int(tagHeader[1]))
            tags[tag] = tagData
        }
    }

    func data() -> Data {
        var header = Data([
            0xB6,
            0x9E,
            0x01, // version
            flags.rawValue, // flags
            algorithm.rawValue,
            kdf.rawValue,
            compression.rawValue,
            UInt8(tags.count),
        ])
        for (tag, tagData) in tags {
            header.append(tag.rawValue)
            header.append(UInt8(tagData.count))
            header.append(tagData)
        }
        return header
    }

    func deriveKey(_ data: Data) -> SymmetricKey {
        kdf.derive(data, tags: tags)
    }

    func encrypt(_ data: Data, key: SymmetricKey, counter: Int) throws -> Data {
        try algorithm.encrypt(data, key: key, tags: tags, counter: counter)
    }

    func decrypt(_ data: Data, key: SymmetricKey, counter: Int) throws -> Data {
        try algorithm.decrypt(data, key: key, tags: tags, counter: counter)
    }
}

protocol PZipKey {
    var kdf: KeyDerivation { get }
    var material: Data { get }

    func tags() -> PZipTags
}

public struct RawKey: PZipKey {
    var kdf = KeyDerivation.Raw
    var material: Data

    init(_ data: Data) {
        material = data
    }

    func tags() -> PZipTags {
        [:]
    }
}

public struct Password: PZipKey {
    var kdf = KeyDerivation.PBKDF2_SHA256
    var material: Data
    var iterations: UInt32

    init(_ password: String, iterations: UInt32 = 200_000) {
        material = password.data(using: .utf8)!
        self.iterations = iterations
    }

    func tags() -> PZipTags {
        var rounds = iterations.bigEndian
        return [
            .Salt: Data(randomOfLength: 32)!,
            .Iterations: Data(bytes: &rounds, count: 4),
        ]
    }
}

public enum PZipSource {
    case File(file: FileHandle)
    case Stream(stream: InputStream)

    func read(_ size: Int) -> Data {
        switch self {
        case let .File(file):
            return file.readData(ofLength: size)
        case let .Stream(stream):
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
            defer {
                buffer.deallocate()
            }
            let count = stream.read(buffer, maxLength: size)
            return Data(bytes: buffer, count: count)
        }
    }
}

public enum PZipDestination {
    case File(file: FileHandle)
    case Stream(stream: OutputStream)

    func write(_ data: Data) {
        switch self {
        case let .File(file):
            file.write(data)
        case let .Stream(stream):
            _ = data.withUnsafeBytes {
                stream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: data.count)
            }
        }
    }
}

public class PZipWriter {
    static let DEFAULT_BLOCK_SIZE = 1 << 18

    var output: PZipDestination
    var blockSize: Int
    var buffer: Data
    var pzip: PZipHeader
    var key: SymmetricKey
    var counter = 0
    var written = 0

    init<K: PZipKey>(_ to: PZipDestination, key: K, algorithm: Algorithm = .AES_GCM_256, compression: Compression = .GZIP, blockSize: Int = DEFAULT_BLOCK_SIZE) {
        output = to
        self.blockSize = blockSize
        buffer = Data(capacity: self.blockSize * 2)

        var tags: [Tag: Data] = [:]
        tags.merge(algorithm.tags()) { _, new in new }
        tags.merge(key.tags()) { _, new in new }

        pzip = PZipHeader(algorithm: algorithm, kdf: key.kdf, compression: compression, tags: tags)
        self.key = pzip.deriveKey(key.material)
    }

    func writeBlock(_ data: Data, last: Bool = false) {
        if counter == 0 {
            output.write(pzip.data())
        }
        if data.count > 0 {
            let compressed = try! pzip.compression.compress(data)
            let ciphertext = try! pzip.encrypt(compressed, key: key, counter: counter)
            var header = (UInt32(ciphertext.count) | (last ? PZipHeader.LAST_BLOCK : 0)).bigEndian
            output.write(Data(bytes: &header, count: 4))
            output.write(ciphertext)
            written += data.count
            counter += 1
        } else {
            var header = last ? PZipHeader.LAST_BLOCK.bigEndian : UInt32(0)
            output.write(Data(bytes: &header, count: 4))
        }
    }

    func write<T: DataProtocol>(_ data: T) {
        buffer.append(contentsOf: data)
        while buffer.count >= blockSize {
            let range = 0 ..< blockSize
            writeBlock(buffer.subdata(in: range))
            buffer.removeSubrange(range)
        }
    }

    func finalize() {
        writeBlock(buffer, last: true)
        if pzip.flags.contains(.AppendLength) {
            var size = UInt64(written).bigEndian
            output.write(Data(bytes: &size, count: 8))
        }
    }
}

public class PZipReader {
    var input: PZipSource
    var buffer: Data
    var pzip: PZipHeader
    var key: SymmetricKey
    var counter = 0
    var bytesRead: UInt64 = 0
    var eof = false

    init(_ from: PZipSource, keyMaterial: Data) {
        input = from
        buffer = Data()
        pzip = PZipHeader(from: from)
        key = pzip.deriveKey(keyMaterial)
    }

    func readBlock() -> Data? {
        if eof {
            return nil
        }
        let header: UInt32 = input.read(4).readInt()
        let size = header & 0x00FF_FFFF
        eof = (header & PZipHeader.LAST_BLOCK) != 0
        var plaintext: Data
        if size > 0 {
            let ciphertext = input.read(Int(size))
            let compressed = try! pzip.decrypt(ciphertext, key: key, counter: counter)
            plaintext = try! pzip.compression.decompress(compressed)
            counter += 1
            bytesRead += UInt64(plaintext.count)
        } else {
            plaintext = Data()
        }
        if eof {
            let checkSize: UInt64 = input.read(8).readInt()
            if checkSize != bytesRead {
                print("size check failed", checkSize, bytesRead)
            }
        }
        return plaintext
    }

    func read(_ size: Int) -> Data {
        while buffer.count < size {
            if let block = readBlock() {
                buffer.append(block)
            } else {
                break
            }
        }
        let range = 0 ..< min(size, buffer.count)
        let data = buffer.subdata(in: range)
        buffer.removeSubrange(range)
        return data
    }

    func readToEnd() -> Data {
        while let block = readBlock() {
            buffer.append(block)
        }
        let data = Data(buffer)
        buffer.removeAll()
        return data
    }
}

func pbkdf2_sha256(_ password: Data, salt: Data, iterations: Int, keyByteCount: Int = 32) -> Data? {
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)

    let derivationStatus = derivedKeyData.withUnsafeMutableBytes { (derivedKeyBytes: UnsafeMutableRawBufferPointer) -> Int32 in
        password.withUnsafeBytes { (passwordBytes: UnsafeRawBufferPointer) -> Int32 in
            salt.withUnsafeBytes { (saltBytes: UnsafeRawBufferPointer) -> Int32 in
                let passPtr = passwordBytes.bindMemory(to: Int8.self).baseAddress
                let saltPtr = saltBytes.bindMemory(to: UInt8.self).baseAddress
                let keyPtr = derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress
                return CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passPtr,
                    password.count,
                    saltPtr,
                    salt.count,
                    CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    keyPtr,
                    keyByteCount
                )
            }
        }
    }

    if derivationStatus != kCCSuccess {
        print("Error in pbkdf2: \(derivationStatus)")
        return nil
    }

    return derivedKeyData
}

func hkdf_sha256(_ seed: Data, salt: Data, info: Data, outputSize: Int = 32) -> Data? {
    // It would be nice to make this generic over <H: HashFunction> if HashFunction had byteCount instead of each hash individually implementing it.
    let iterations = UInt8(ceil(Double(outputSize) / Double(SHA256.byteCount)))
    guard iterations <= 255 else {
        return nil
    }

    let prk = HMAC<SHA256>.authenticationCode(for: seed, using: SymmetricKey(data: salt))
    let key = SymmetricKey(data: prk)
    var hkdf = Data()
    var value = Data()

    for i in 1 ... iterations {
        value.append(info)
        value.append(i)

        let code = HMAC<SHA256>.authenticationCode(for: value, using: key)
        hkdf.append(contentsOf: code)

        value = Data(code)
    }

    return hkdf.prefix(outputSize)
}

public extension Data {
    func hexEncodedString(upper: Bool = true, spaced: Bool = false) -> String {
        var format = upper ? "%02hhX" : "%02hhx"
        if spaced { format += " " }
        return map { String(format: format, $0) }.joined()
    }
}

public extension String {
    func hexDecodedData() -> Data? {
        let len = count / 2
        var data = Data(capacity: len)
        for i in 0 ..< len {
            let j = index(startIndex, offsetBy: i * 2)
            let k = index(j, offsetBy: 2)
            let bytes = self[j ..< k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        return data
    }
}

public extension Data {
    init?(randomOfLength length: Int) {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        if status == errSecSuccess {
            self.init(bytes)
        } else {
            return nil
        }
    }

    func readInt<T: FixedWidthInteger>() -> T {
        if (count * 8) < T.bitWidth {
            // Should probably throw an error here.
            return T.zero
        }
        return T(bigEndian: withUnsafeBytes {
            $0.load(as: T.self)
        })
    }

    func deriveNonce(_ counter: Int) -> AES.GCM.Nonce {
        // Convert the counter to big endian bytes.
        var big = UInt32(counter).bigEndian
        var ctr = Data(bytes: &big, count: 4)
        // Pad the counter bytes to be the same length as this Data.
        while ctr.count < count {
            ctr.insert(0, at: 0)
        }
        // XOR ourself with the counter bytes into a new UInt8 sequence.
        var result = [UInt8](repeating: 0, count: count)
        let b1 = [UInt8](self), b2 = [UInt8](ctr)
        for i in 0 ..< count {
            result[i] = b1[i] ^ b2[i]
        }
        return try! AES.GCM.Nonce(data: result)
    }
}
