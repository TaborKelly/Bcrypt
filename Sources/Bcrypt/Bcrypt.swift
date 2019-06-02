//
//  Bcrypt
//
//  Created by Felipe Florencio Garcia on 3/14/17.
//  Copyright © 2017 Felipe Florencio Garcia.
//  Copyright © 2019 Tabor Kelly
//
//  Originally created by Joe Kramer https://github.com/meanjoe45/JKBCrypt
// Then modified by Felipe Florencio Garcia: https://github.com/felipeflorencio/BCryptSwift
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ----------------------------------------------------------------------
//
// This Swift port is based on the Objective-C port by Jay Fuerstenberg.
// https://github.com/jayfuerstenberg/JFCommon
//
// ----------------------------------------------------------------------
//
// The Objective-C port is based on the original Java implementation by Damien Miller
// found here: http://www.mindrot.org/projects/jBCrypt/
// In accordance with the Damien Miller's request, his original copyright covering
// his Java implementation is included here:
//
// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

import Foundation

// MARK: - Class Extensions

public enum BcryptError: Error {
    /// Rounds was less than 4 or more than 31
    case invalidRounds
    /// The salt was incorrectly formatted
    case invalidSalt
}

public class Bcrypt: NSObject {
    fileprivate var p : UnsafeMutablePointer<Int32>! // [Int32]
    fileprivate var s : UnsafeMutablePointer<Int32>! // [Int32]

    let plen: Int = 18
    let slen: Int = 1024

    override init() {
        self.p = nil
        self.s = nil
    }

    /**
     Generates a salt with a defaulted set of 10 rounds.
     rounds [4, 31]

     :returns: String    The generated salt.
     */
    public class func generateSalt(rounds: UInt = 10) throws -> String {
        if rounds < 4 || rounds > 31 {
            throw BcryptError.invalidRounds
        }

        let randomData : [Int8] = BcryptRandom.generateRandomSignedDataOfLength(BCRYPT_SALT_LEN)

        var salt : String
        salt =  "$2a$" + ((rounds < 10) ? "0" : "") + "\(rounds)" + "$"
        salt += Bcrypt.encodeData(randomData, ofLength: UInt(randomData.count))

        return salt
    }

    /**
     Hashes the provided password with the provided salt.

     :param: password    The password to hash.
     :param: salt        The salt to use in the hash.

     The `salt` must be 16 characters in length. Also, the `salt` must be properly formatted
     with accepted version, revision, and salt rounds. If any of this is not true, nil is
     returned.

     :returns: String?  The hashed password.
     */
    public class func hashPassword(password: String, salt: String) throws -> String {
        var bCrypt: Bcrypt
        var realSalt: String
        var minor: Character = "\000"[0]
        var off: Int = 0

        // If the salt length is too short, it is invalid
        if salt.count < 16 {
            throw BcryptError.invalidSalt
        }

        // If the salt does not start with "$2", it is an invalid version
        if salt[0] != "$" || salt[1] != "2" {
            throw BcryptError.invalidSalt
        }

        if salt[2] == "$" {
            off = 3
        }
        else {
            off = 4
            minor = salt[2]
            if (minor != "y" && minor != "a" && minor != "b") || salt[3] != "$" {
                // Invalid salt revision.
                throw BcryptError.invalidSalt
            }
        }

        // Extract number of rounds
        if salt[(Int)(off+2)] > "$" {
            // Missing salt rounds
            throw BcryptError.invalidSalt
        }

        var range = Range(uncheckedBounds: (lower: off, upper: off + 2))
        guard let extactedRounds = Int(salt[range]) else {
            // Invalid number of rounds
            throw BcryptError.invalidSalt
        }
        let rounds : Int = extactedRounds

        range = Range(uncheckedBounds: (lower: off + 3, upper: off + 25))
        realSalt = salt[range]

        var passwordPreEncoding : String = password
        if minor >= "a" {
            passwordPreEncoding += "\0"
        }

        let passwordData: [Int8] = [UInt8](passwordPreEncoding.utf8).map {
            Int8(bitPattern: $0)
        }

        let saltData: [Int8] = Bcrypt.decode_base64(realSalt, ofMaxLength: BCRYPT_SALT_LEN)

        bCrypt = Bcrypt( )
        let hashedData = try bCrypt.hashPassword(passwordData, withSalt: saltData, numberOfRounds: rounds)

        var hashedPassword : String = "$2" + ((minor >= "a") ? String(minor) : "") + "$"

        hashedPassword += ((rounds < 10) ? "0" : "") + "\(rounds)" + "$"

        let saltString = Bcrypt.encodeData(saltData, ofLength: UInt(saltData.count))

        let hashedString = Bcrypt.encodeData(hashedData, ofLength: 23)

        return hashedPassword + saltString + hashedString
    }

    public class func hashPassword(password: String, rounds: UInt) throws -> String {
        let salt = try Bcrypt.generateSalt(rounds: rounds)
        let hashedPassword = try Bcrypt.hashPassword(password: password, salt: salt)
        return hashedPassword
    }

    /**
     Hashes the provided password with the provided hash and compares if the two hashes are equal.

     :param: password    The password to hash.
     :param: hash        The hash to use in generating and comparing the password.

     The `hash` must be properly formatted with accepted version, revision, and salt rounds. If
     any of this is not true, nil is returned.

     :returns: Bool?     TRUE if the password hash matches the given hash; FALSE if the two do not
     match; nil if hash is improperly formatted.
     */
    public class func verifyPassword(password: String, hash: String) throws -> Bool {
        let hashedPassword = try Bcrypt.hashPassword(password: password, salt: hash)

        return (hashedPassword == hash)
    }

    // MARK: - Private Class Methods

    /**
     Encodes an NSData composed of signed chararacters and returns slightly modified
     Base64 encoded string.

     :param: data    The data to be encoded. Passing nil will result in nil being returned.
     :param: length  The length. Must be greater than 0 and no longer than the length of data.

     :returns: String  A Base64 encoded string.
     */
    class fileprivate func encodeData(_ data: [Int8], ofLength length: UInt) -> String {

        if data.count == 0 || length == 0 {
            // Invalid data so return nil.
            return String()
        }

        var len : Int = Int(length)
        if len > data.count {
            len = data.count
        }

        var offset : Int = 0
        var c1 : UInt8
        var c2 : UInt8
        var result : String = String()

        var dataArray : [UInt8] = data.map {
            UInt8(bitPattern: Int8($0))
        }

        while offset < len {
            c1 = dataArray[offset] & 0xff
            offset += 1
            result.append(base64_code[Int((c1 >> 2) & 0x3f)])
            c1 = (c1 & 0x03) << 4
            if offset >= len {
                result.append(base64_code[Int(c1 & 0x3f)])
                break
            }

            c2 = dataArray[offset] & 0xff
            offset += 1
            c1 |= (c2 >> 4) & 0x0f
            result.append(base64_code[Int(c1 & 0x3f)])
            c1 = (c2 & 0x0f) << 2
            if offset >= len {
                result.append(base64_code[Int(c1 & 0x3f)])
                break
            }

            c2 = dataArray[offset] & 0xff
            offset += 1
            c1 |= (c2 >> 6) & 0x03
            result.append(base64_code[Int(c1 & 0x3f)])
            result.append(base64_code[Int(c2 & 0x3f)])
        }

        return result
    }

    /**
     Returns the Base64 encoded signed character of the provided unicode character.

     :param: x   The 16-bit unicode character whose Base64 counterpart, if any, will be returned.

     :returns: Int8  The Base64 encoded signed character or -1 if none exists.
     */
    class fileprivate func char64of(_ x: Character) -> Int8 {
        let xAsInt : Int32 = Int32(x.utf16Value())

        if xAsInt < 0 || xAsInt > 128 - 1 {
            // The character would go out of bounds of the pre-calculated array so return -1.
            return -1
        }

        // Return the matching Base64 encoded character.
        return index_64[Int(xAsInt)]
    }

    /**
     Decodes the provided Base64 encoded string to an [Int8] composed of signed characters.

     :param: s       The Base64 encoded string. If this is nil, nil will be returned.
     :param: maxolen The maximum number of characters to decode. If this is not greater than 0 nil will be returned.

     :returns: [Int8]   An [Int8] or nil if the arguments are invalid.
     */
    class fileprivate func decode_base64(_ s: String, ofMaxLength maxolen: Int) -> [Int8] {
        var off : Int = 0
        let slen : Int = s.count
        var olen : Int = 0
        var result : [Int8] = [Int8](repeating: 0, count: maxolen)

        var c1 : Int8
        var c2 : Int8
        var c3 : Int8
        var c4 : Int8
        var o : Int8

        while off < slen - 1 && olen < maxolen {
            c1 = Bcrypt.char64of(s[off])
            off += 1
            c2 = Bcrypt.char64of(s[off])
            off += 1
            if c1 == -1 || c2 == -1 {
                break
            }

            o = c1 << 2
            o |= (c2 & 0x30) >> 4
            result[olen] = o
            olen += 1
            if olen >= maxolen || off >= slen {
                break
            }

            c3 = Bcrypt.char64of(s[Int(off)])
            off += 1
            if c3 == -1 {
                break
            }

            o = (c2 & 0x0f) << 4
            o |= (c3 & 0x3c) >> 2
            result[olen] = o
            olen += 1
            if olen >= maxolen || off >= slen {
                break
            }

            c4 = Bcrypt.char64of(s[off])
            off += 1
            o = (c3 & 0x03) << 6
            o |= c4
            result[olen] = o
            olen += 1
        }

        return Array(result[0..<olen])
    }

    /**
     Cyclically extracts a word of key material from the provided NSData.

     :param: d       The NSData from which the word will be extracted.
     :param: offp    The "pointer" (as a one-entry array) to the current offset into data.

     :returns: Int32 The next word of material from the data.
     */
    class fileprivate func streamToWordWithData(_ data: UnsafeMutablePointer<Int8>, ofLength length: Int, off offp: inout Int32) -> Int32 {
        var word : Int32 = 0
        var off  : Int32 = offp

        for _ in 0..<4{
            word = (word << 8) | (Int32(data[Int(off)]) & 0xff)
            off = (off + 1) % Int32(length)
        }

        offp = off
        return word
    }

    // MARK: - Private Instance Methods

    /**
     Hashes the provided password with the salt for the number of rounds.

     :param: password        The password to hash.
     :param: salt            The salt to use in the hash.
     :param: numberOfRounds  The number of rounds to apply.

     The salt must be 16 characters in length. The `numberOfRounds` must be between 4
     and 31 inclusively. If any of this is not true, nil is returned.

     :returns: [Int8]?  The hashed password.
     */
    fileprivate func hashPassword(_ password: [Int8], withSalt salt: [Int8], numberOfRounds: Int) throws -> [Int8] {
        var rounds : Int
        var j      : Int
        let clen   : Int = 6
        var cdata  : [Int32] = bf_crypt_ciphertext

        if numberOfRounds < 4 || numberOfRounds > 31 {
            // Invalid number of rounds
            throw BcryptError.invalidRounds
        }

        rounds = 1 << numberOfRounds
        if salt.count != 16 {
            // Invalid salt length
            throw BcryptError.invalidSalt
        }

        self.initKey()
        self.enhanceKeyScheduleWithData(data: salt, key: password)

        for _ in 0..<rounds{
            self.key(password)
            self.key(salt)
        }

        for _ in 0..<64 {
            for j in 0..<(clen >> 1) {
                self.encipher(&cdata, off: j << 1)
            }
        }

        var result : [Int8] = [Int8](repeating: 0, count: clen * 4)

        j = 0
        for i in 0..<clen {
            result[j] = Int8(truncatingIfNeeded: (cdata[i] >> 24) & 0xff)
            j += 1
            result[j] = Int8(truncatingIfNeeded: (cdata[i] >> 16) & 0xff)
            j += 1
            result[j] = Int8(truncatingIfNeeded: (cdata[i] >> 8) & 0xff)
            j += 1
            result[j] = Int8(truncatingIfNeeded: cdata[i] & 0xff)
            j += 1
        }

        deinitKey()
        return result
    }

    /**
     Enciphers the provided array using the Blowfish algorithm.

     :param: lr  The left-right array containing two 32-bit half blocks.
     :param: off The offset into the array.

     :returns: <void>
     */
    fileprivate func encipher(_ lr: UnsafeMutablePointer<Int32>, off: Int) {
        if off < 0 {
            // Invalid offset.
            return
        }

        var n : Int32
        var l : Int32 = lr[off]
        var r : Int32 = lr[off + 1]

        l ^= p[0]
        var i : Int = 0
        while i <= BLOWFISH_NUM_ROUNDS - 2 {
            // Feistel substitution on left word
            n = s.advanced(by: Int((l >> 24) & 0xff)).pointee
            n = n &+ s.advanced(by: Int(0x100 | ((l >> 16) & 0xff))).pointee
            n ^= s.advanced(by: Int(0x200 | ((l >> 8) & 0xff))).pointee
            n = n &+ s.advanced(by: Int(0x300 | (l & 0xff))).pointee
            i += 1
            r ^= n ^ p.advanced(by: i).pointee

            // Feistel substitution on right word
            n = s.advanced(by: Int((r >> 24) & 0xff)).pointee
            n = n &+ s.advanced(by: Int(0x100 | ((r >> 16) & 0xff))).pointee
            n ^= s.advanced(by: Int(0x200 | ((r >> 8) & 0xff))).pointee
            n = n &+ s.advanced(by: Int(0x300 | (r & 0xff))).pointee
            i += 1
            l ^= n ^ p.advanced(by: i).pointee
        }

        lr[off] = r ^ p.advanced(by: BLOWFISH_NUM_ROUNDS + 1).pointee
        lr[off + 1] = l
    }

    /**
     Initializes the blowfish key schedule.

     :returns: <void>
     */
    fileprivate func initKey() {
        p = UnsafeMutablePointer<Int32>.allocate(capacity: P_orig.count)
        p.initialize(from: UnsafeMutablePointer<Int32>(mutating: P_orig), count: P_orig.count)

        s = UnsafeMutablePointer<Int32>.allocate(capacity: S_orig.count)
        s.initialize(from: UnsafeMutablePointer<Int32>(mutating: S_orig), count: S_orig.count)
    }

    fileprivate func deinitKey() {

        p.deinitialize(count: P_orig.count)
        p.deallocate()

        s.deinitialize(count:S_orig.count)
        s.deallocate()
    }

    /**
     Keys the receiver's blowfish cipher using the provided key.

     :param: key The array containing the key.

     :returns: <void>
     */
    fileprivate func key(_ key: [Int8]) {
        var koffp : Int32 = 0
        var lr    : [Int32] = [0, 0]

        let keyPointer : UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>(mutating: key)
        let keyLength : Int = key.count

        for i in 0..<plen {
            p[i] = p[i] ^ Bcrypt.streamToWordWithData(keyPointer, ofLength: keyLength, off: &koffp)
        }

        var i = 0

        while i < plen {
            self.encipher(&lr, off: 0)
            p[i] = lr[0]
            p[i + 1] = lr[1]
            i += 2
        }

        i = 0

        while i < slen {
            self.encipher(&lr, off: 0)
            s[i] = lr[0]
            s[i + 1] = lr[1]
            i += 2
        }

    }

    /**
     Performs the "enhanced key schedule" step described by Provos and Mazieres
     in "A Future-Adaptable Password Scheme"
     http://www.openbsd.org/papers/bcrypt-paper.ps

     :param: data    The salt data.
     :param: key     The password data.

     :returns: <void>
     */
    fileprivate func enhanceKeyScheduleWithData(data: [Int8], key: [Int8]) {
        var koffp: Int32 = 0
        var doffp: Int32 = 0

        var lr: [Int32] = [0, 0]



        let keyPointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>(mutating: key)
        let keyLength: Int = key.count
        let dataPointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>(mutating: data)
        let dataLength: Int = data.count

        for i in 0..<plen {
            p[i] = p[i] ^ Bcrypt.streamToWordWithData(keyPointer, ofLength: keyLength, off:&koffp)
        }

        var i = 0

        while i < plen {
            lr[0] ^= Bcrypt.streamToWordWithData(dataPointer, ofLength: dataLength, off: &doffp)
            lr[1] ^= Bcrypt.streamToWordWithData(dataPointer, ofLength: dataLength, off: &doffp)
            self.encipher(&lr, off: 0)
            p[i] = lr[0]
            p[i + 1] = lr[1]

            i += 2
        }

        i = 0

        while i < slen {
            lr[0] ^= Bcrypt.streamToWordWithData(dataPointer, ofLength: dataLength, off: &doffp)
            lr[1] ^= Bcrypt.streamToWordWithData(dataPointer, ofLength: dataLength, off: &doffp)
            self.encipher(&lr, off: 0)
            s[i] = lr[0]
            s[i + 1] = lr[1]

            i += 2
        }
    }
}
