import XCTest

import BcryptTests

var tests = [XCTestCaseEntry]()
tests += BcryptTests.allTests()
XCTMain(tests)
