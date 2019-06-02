import XCTest
@testable import Bcrypt

final class BcryptTests: XCTestCase {
    static var allTests = [
        ("testVerifyPassword", testVerifyPassword),
        ("testRoundTrip", testVerifyPassword),
        ("testInvalidRounds", testInvalidRounds),
    ]

    func testVerifyPassword() {
        let tests = [
            ("Lorem ipsum",                        "$2a$04$iKEdFSX4maFRvSf2yIYUXuVhJtmg6ssFioZ/4MRPpXC8e1ZCNp3GC"),
            ("dolor sit amet",                     "$2a$05$ya5vlx.W4rTCpW5/bT63j.rnOsutrnEdiICFHA3PQa3ZPpl2dtzJW"),
            ("consectetur",                        "$2a$06$71q7eRv/yEG.54k3mlQPzOM.an8ivpBFGlVMSIGt9PiMX6rzRZWYi"),
            ("adipiscing",                         "$2a$07$3rNponm3HOX5l/BJc6cPVOlQE.UdACG3EnXoWkTtidULd6CnRBAZC"),
        ]

        for (password, hash) in tests {
            XCTAssertTrue(try Bcrypt.verifyPassword(password: password, hash: hash))
        }
    }

    func testRoundTrip() {
        do {
            let passwords = ["Lorem ipsum", "dolor sit amet", "consectetur", "adipiscing"]
            var rounds: UInt = 4
            for p in passwords {
                let hashedPassword = try Bcrypt.hashPassword(password: p, rounds: rounds)
                XCTAssertTrue(try Bcrypt.verifyPassword(password: p, hash: hashedPassword))
                rounds = rounds + 1
            }
        } catch {
            XCTFail("\(error)")
        }
    }

    func testInvalidRounds() {
        XCTAssertThrowsError(try Bcrypt.generateSalt(rounds: 0))
        XCTAssertThrowsError(try Bcrypt.generateSalt(rounds: 1))
        XCTAssertThrowsError(try Bcrypt.generateSalt(rounds: 2))
        XCTAssertThrowsError(try Bcrypt.generateSalt(rounds: 3))
        XCTAssertThrowsError(try Bcrypt.generateSalt(rounds: 32))
    }
}
