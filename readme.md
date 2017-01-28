### Simple ECDSA library

A simple ECDSA library can:

- Generate KeyPairs
- Sign & Verify
- Currently Supports Curve P256
- Keys and signature are encoded from string -> DER of ASN.1 -> Hex. 
- Supports import of DER-ASN.1->Hex encoded keys.

## Example

```js
let s = new SimpleECDSA(CurveP265)
let privKey = s.getPrivKey()         // DER-ASN.1->Hex
let sig = s.sign("hello")            // DER-ASN.1->Hex signature
let verified = SimpleECDSA.verify(s.getPubKey(), CurveP265, "hello", sig)
console.log(verified)

# Other methods
SimpleECDSA.genKey()                // refresh the internal key in SimpleECDSA instance
SimpleECDSA.getPrivKey()            // get the private key
SimpleECDSA.loadFromPubKey(key)     // import a DER-ASN.1->Hex encode public key
SimpleECDSA.loadFromPrivKey(key)    // import a DER-ASN.1->Hex encode private key
SimpleECDSA.isValidPubKey(key)      // Check the whether a public key is decodable.
```

