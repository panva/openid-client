# Type Alias: JWK

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

• **JWK** = `object`

A JSON Web Key with standard JOSE and supported extension parameters.

> [!NOTE]\
> This is declared as a type alias rather than an interface so that it remains bidirectionally
> assignable with the `JsonWebKey` types shipped by `@types/node` and `lib.dom` without accepting
> arbitrary parameters itself.

Application-specific extension parameters can be represented by intersecting this type with a
type that declares them.

## Properties

### alg?

• `readonly` `optional` **alg?**: `string`

JWK "alg" (Algorithm) Parameter

***

### crv?

• `readonly` `optional` **crv?**: `string`

- EC JWK "crv" (Curve) Parameter
- OKP JWK "crv" (The Subtype of Key Pair) Parameter

***

### d?

• `readonly` `optional` **d?**: `string`

- Private RSA JWK "d" (Private Exponent) Parameter
- Private EC JWK "d" (ECC Private Key) Parameter
- Private OKP JWK "d" (The Private Key) Parameter

***

### dp?

• `readonly` `optional` **dp?**: `string`

Private RSA JWK "dp" (First Factor CRT Exponent) Parameter

***

### dq?

• `readonly` `optional` **dq?**: `string`

Private RSA JWK "dq" (Second Factor CRT Exponent) Parameter

***

### e?

• `readonly` `optional` **e?**: `string`

RSA JWK "e" (Exponent) Parameter

***

### ext?

• `readonly` `optional` **ext?**: `boolean`

JWK "ext" (Extractable) Parameter

***

### k?

• `readonly` `optional` **k?**: `string`

Oct JWK "k" (Key Value) Parameter

***

### key\_ops?

• `readonly` `optional` **key\_ops?**: `string`[]

JWK "key_ops" (Key Operations) Parameter

***

### kid?

• `readonly` `optional` **kid?**: `string`

JWK "kid" (Key ID) Parameter

***

### kty?

• `readonly` `optional` **kty?**: `string`

JWK "kty" (Key Type) Parameter

***

### n?

• `readonly` `optional` **n?**: `string`

RSA JWK "n" (Modulus) Parameter

***

### oth?

• `readonly` `optional` **oth?**: `object`[]

RSA JWK "oth" (Other Primes Info) Parameter

#### d?

• `optional` **d?**: `string`

The Factor CRT Exponent

#### r?

• `optional` **r?**: `string`

The Prime Factor

#### t?

• `optional` **t?**: `string`

The Factor CRT Coefficient

***

### p?

• `readonly` `optional` **p?**: `string`

Private RSA JWK "p" (First Prime Factor) Parameter

***

### priv?

• `readonly` `optional` **priv?**: `string`

AKP JWK "priv" (Private Key) Parameter

***

### pub?

• `readonly` `optional` **pub?**: `string`

AKP JWK "pub" (Public Key) Parameter

***

### q?

• `readonly` `optional` **q?**: `string`

Private RSA JWK "q" (Second Prime Factor) Parameter

***

### qi?

• `readonly` `optional` **qi?**: `string`

Private RSA JWK "qi" (First CRT Coefficient) Parameter

***

### use?

• `readonly` `optional` **use?**: `string`

JWK "use" (Public Key Use) Parameter

***

### x?

• `readonly` `optional` **x?**: `string`

- EC JWK "x" (X Coordinate) Parameter
- OKP JWK "x" (The public key) Parameter

***

### x5c?

• `readonly` `optional` **x5c?**: `string`[]

JWK "x5c" (X.509 Certificate Chain) Parameter

***

### x5t?

• `readonly` `optional` **x5t?**: `string`

JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter

***

### x5t#S256?

• `readonly` `optional` **x5t#S256?**: `string`

JWK "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter

***

### x5u?

• `readonly` `optional` **x5u?**: `string`

JWK "x5u" (X.509 URL) Parameter

***

### y?

• `readonly` `optional` **y?**: `string`

EC JWK "y" (Y Coordinate) Parameter
