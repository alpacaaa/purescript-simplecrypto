
# purescript-simplecrypto

A set of useful cryptographic utilities for blockchain development.



### Features

- ECDSA public/private key generation
- ECDSA signatures
- SHA256/SHA512/RIPEMD160 hashing
- Base58 encoding/decoding



### Install

`bower install --save purescript-simplecrypto`

You will also need to pull down a couple of packages from npm.

`npm install --save secp256k1 base-x`



### Examples

I like qualified imports
```haskell
import Crypto.Simple as Crypto
```

##### Hash a string

```haskell
Crypto.hash Crypto.SHA256 "purescript ftw"
-- 62a2f55959f8c4abd9d069ec3cd130f7570c02bf9d66e6b28261834ee02d3319
```

##### Generate ECDSA key pair
```haskell
main = do
  keys <- Crypto.generateKeyPair
  log ("Public key: " <> show keys.public)
  log ("Private key: " <> show keys.private)

-- Public key: 023a8e963fa94ca2f2ee6d71e8344c66f592f12aa24d4f07aeb6f22f83317d817a
-- Private key: 121a5b5e1a783cba15d7e2ae753f0d8dc97b37aed19579ef1f0dbf13c7280a51
```

##### Sign and verify a message
```haskell
isValidMsg true  = "Signature match!"
isValidMsg false = "Message was not signed by the owner of this public key"

main = do
  { private, public } <- Crypto.generateKeyPair
  let msg        = Crypto.hash Crypto.SHA256 "purescript ftw"
  let signature  = Crypto.sign private msg
  let verify sig = isValidMsg $ Crypto.verify public sig msg
  log $ maybe "Something went wrong" verify signature
```


##### Base58 encoding/decoding
```haskell
main = do
  let msg     = Crypto.hash Crypto.SHA256 "purescript ftw"
  let encoded = Crypto.baseEncode Crypto.BASE58 msg
  let decoded = map (Crypto.baseDecode Crypto.BASE58) encoded
  log $ maybe "Something went wrong" (\d -> "Decoded: " <> show d) decoded
```


##### Generating a compressed Bitcoin address
```haskell
btcAddress :: Crypto.PublicKey -> Maybe Crypto.EncodeData
btcAddress pk = show pk
  # Crypto.hash Crypto.SHA256
  # Crypto.hash Crypto.SHA256
  # Crypto.hash Crypto.RIPEMD160
  # Crypto.baseEncode Crypto.BASE58

main = do
  { public } <- Crypto.generateKeyPair
  let address = btcAddress public
  log $ maybe "Something went wrong" (\bAddr -> "BTC address: " <> show bAddr) address

  -- BTC address: 2coF1xKLYoUCoQc3nFYs9NgoauQJ
```
