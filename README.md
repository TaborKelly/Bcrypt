# Bcrypt
This is a Swift implementation of [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) that only relies on Foundation.

## Usage

```swift
/// given a plaintext password, return the password hash
func hashMyPassword(password: String) throws -> String {
    // It's this easy
    let hashedPassword = try Bcrypt.hashPassword(password: password, rounds: 4)
    return hashedPassword
}

/// Check to see if a password matches the password hash
func checkMyPassword(password: String, passwordHash: String) throws -> Bool {
    return try Bcrypt.verifyPassword(password: password, hash: passwordHash)
}
```

## Errors
If an error is thrown it will be of this type:
```swift
public enum BcryptError: Error {
    /// Rounds was less than 4 or more than 31
    case invalidRounds
    /// The salt was incorrectly formatted
    case invalidSalt
}
```

## Open source
This is very open source. It is based on work by [Felipe Florencio Garcia](https://github.com/felipeflorencio/BCryptSwift) that is based on work by [Jay Fuerstenberg](https://github.com/jayfuerstenberg/JFCommon) that is based on work by [Damien Miller](http://www.mindrot.org/projects/jBCrypt/).

## License
This is licensed under the [Apache 2.0 software license](http://www.apache.org/licenses/LICENSE-2.0) which is as far as I know compatible with all prior works.
