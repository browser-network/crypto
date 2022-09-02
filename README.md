# Browser Network Crypto

This package is just a wrapper around
[`eccrypto`](https://github.com/bitchan/eccrypto). It's meant to be used with the
browser network and accompanying browser network apps. It's only for
convenience. If you're looking to bring cryptography into your non browser
network application, you should probably use `eccrypto` or another cryptography
library directly instead of using this.

## Installation

```sh
npm install @browser-network/crypto
```

or

```html
<script src="//unpkg.com/@browser-network/network/umd/crypto.min.js"></script>
```

## Usage

```ts
import * as bnc from 'browser-network/crypto'

// Generate a secret (private key) as used by browser-network
const secret = bnc.generateSecret()

// Get the public key mathematically derived from a given secret
const pubKey = bnc.derivePubKey(secret)

// Turn a given string into a `Uint8Array` buffer that eccrypto uses.
const buf = bnc.stob("Serena's ol bus")

// Turn the `Uint8Array` buffer that eccrypto uses into a string for export
const str = bnc.btos(buf) // "Serena's ol bus"

// Create a hash from an object
const has = bnc.hash({ some: 'object' }) // => `Uint8Array`

// Take an object and create a signature for it based on a given private key.
const signature = bnc.sign(secret, { some: 'object' })

// Ensure a signature of object by a pubKey comes from that pubKey's associated secret
const isValid = bnc.verifySignature({ some: 'object' }, signature, pubKey) // true
```
