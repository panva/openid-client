# Security Policy

## Supported Versions

The following major versions are currently supported with security updates.

| Version                                                  | End-of-life |
| -------------------------------------------------------- | ----------- |
| [v6.x](https://github.com/panva/openid-client/tree/v6.x) | TBD         |
| [v5.x](https://github.com/panva/openid-client/tree/v5.x) | 2026-04-30  |

End-of-life for the current release will be determined prior to the release of its successor.

## Reporting a Vulnerability

You should report vulnerabilities using the [Github UI](https://github.com/panva/openid-client/security/advisories/new) or via email panva.ip@gmail.com

## Threat Model

This section documents the threat model for `openid-client`, an OAuth 2 / OpenID Connect client API for JavaScript runtimes.

### Purpose and Intended Users

This library is intended for developers building OAuth 2.0 and OpenID Connect client applications in JavaScript runtimes (Node.js, browsers, Cloudflare Workers, Deno, Bun, and other Web-interoperable environments). It provides high-level APIs for implementing secure OAuth/OIDC flows.

### Trust Assumptions

#### Underlying Cryptographic Primitives

This library trusts that the Web Cryptography implementations provided by the runtime are correct and secure. The library delegates all cryptographic operations (signing, verification, encryption, decryption, etc.) to the runtime's Web Cryptography implementation and does not attempt to validate or verify the correctness of these underlying primitives.

#### Runtime Environment

The library assumes it is running in a trusted execution environment. The following are considered outside the scope of this library's threat model:

- **Prototype pollution attacks**: If an attacker can modify JavaScript prototypes, this is considered a vulnerability in the user's application code or the runtime environment, not in this library.
- **Debugger access**: If an attacker has debugger access to the running process, they can inspect memory, modify variables, and bypass security controls. This is a runtime-level compromise, not a library vulnerability.
- **Runtime compromise**: Attacks that compromise the JavaScript runtime itself (e.g., malicious runtime modifications, compromised Node.js binaries, malicious browser extensions with elevated privileges) are not considered attacks on this library.

#### Authorization Server Trust

This library assumes that the Authorization Server metadata endpoints and JWKS endpoints configured by users are legitimate and trusted. Users are responsible for ensuring they connect to trusted Authorization Servers over secure channels (HTTPS). User inputs to discovery functions are considered trusted.

#### Side-Channel Attacks

This library delegates all cryptographic operations to the underlying Web Cryptography API. Any resistance to side-channel attacks (timing attacks, cache attacks, etc.) is entirely dependent on the underlying cryptographic implementations and is outside the scope of this library.

### Security Guarantees

This library aims to provide the following security guarantees:

- **Specification compliance**: Correct implementation of OAuth 2.0, OAuth 2.1, OpenID Connect, and related specifications (including FAPI 1.0/2.0), validated through OpenID Foundation conformance testing.
- **Protocol security mechanisms**: Correct implementation of security mechanisms when used, including:
  - State parameter validation
  - PKCE (Proof Key for Code Exchange)
  - Nonce validation (for OpenID Connect)
  - Issuer identification and validation
  - Token signature verification
  - JWT claims validation (exp, iat, nbf, aud, etc.)
- **Input validation**: Validation of inputs to prevent misuse of the API.

### Out of Scope

#### Key Management

This library does not handle key storage. Users are responsible for securely storing, managing, and distributing cryptographic keys.

#### Memory Clearing

This library does not guarantee that key material or other sensitive data is cleared from memory after use. As long as the user retains references to key objects, the key material may remain in memory. Secure memory management is the responsibility of the user and the runtime environment.

### Threat Actors and Security Properties

This library aims to provide the security properties defined by the OAuth 2.0 Security Best Current Practice and OpenID Connect specifications. For detailed security considerations, refer to [RFC 6819 (OAuth 2.0 Threat Model)](https://www.rfc-editor.org/rfc/rfc6819), [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html), and [OpenID Connect Core 1.0 Security Considerations](https://openid.net/specs/openid-connect-core-1_0.html#Security).

### What is NOT Considered a Vulnerability

The following are explicitly **not** considered vulnerabilities in this library:

- **Prototype pollution** ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)): Attacks that exploit JavaScript prototype pollution are considered vulnerabilities in user application code or the runtime, not this library.
- **Object injection** ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)): Similar to prototype pollution, object injection attacks are outside the scope of this library.
- **Debugger/inspector access** ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)): If an attacker can attach a debugger to the process, they have already compromised the runtime environment.
- **Memory inspection**: Reading process memory, heap dumps, or core dumps to extract key material is a runtime-level attack.
- **Side-channel attacks** ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)): Timing attacks, cache attacks, and other side-channel vulnerabilities in the underlying Web Cryptography implementations are not vulnerabilities in this library.
- **Compromised runtime environment**: Malicious or backdoored JavaScript runtimes, compromised system libraries, or tampered Web Cryptography implementations.
- **Supply chain attacks on the runtime** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): Compromised Node.js binaries, malicious browser builds, or similar supply chain attacks on the execution environment.
- **Supply chain attacks on dependencies** ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)): This library depends on `jose` and `oauth4webapi`. Supply chain compromises of dependencies are not considered vulnerabilities in this library.
- **Denial of service via resource exhaustion** ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)): While the library validates inputs, it does not implement resource limits. Applications should implement their own rate limiting and resource management.
- **Misconfiguration**: Security issues arising from not using available security features (e.g., not using PKCE, using insecure redirect URIs) are the user's responsibility.
- **Untrusted Authorization Servers**: Security issues arising from connecting to untrusted or malicious Authorization Servers are the user's responsibility.
