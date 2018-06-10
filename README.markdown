
# purescript-simplecrypto

A set of useful cryptographic utilities for blockchain development.



### Features

- ECDSA public/private key generation
- ECDSA signatures
- SHA256/SHA512/RIPEMD160 hashing
- Base58 encoding/decoding
- AES support (currently only in CTR mode)



### Install

`bower install --save purescript-simplecrypto`

##### Extra dependencies
You will also need to pull down a couple of packages from npm.

`npm install --save secp256k1 base-x`

AES (optional)

`npm install --save aes-js`



### Examples


##### Hash a string

```haskell
Crypto.hash Crypto.SHA256 "purescript ftw"
-- 62a2f55959f8c4abd9d069ec3cd130f7570c02bf9d66e6b28261834ee02d3319
```

##### Generate ECDSA key pair
```haskell
main = do
  keys <- Crypto.generateKeyPair
  log ("Public key: " <> Crypto.toString keys.public)
  log ("Private key: " <> Crypto.toString keys.private)

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
              # Crypto.toString

  let encoded = Crypto.baseEncode Crypto.BASE58 msg
  let decoded = encoded >>= (Crypto.baseDecode Crypto.BASE58)

  log $ maybe "Something went wrong" (\d -> "Decoded: " <> d) decoded
```


##### Import/Export of keys and signatures
```haskell
import Node.FS.Sync (writeFile, readFile)

sameKey key1 key2 = if key1 == key2 then "They are the same!" else "Wait, what."

main = do
  { private } <- Crypto.generateKeyPair

  -- it works exactly the same for signatures
  let exported = Crypto.exportToBuffer private

  writeFile "privatekey" exported
  contents <- readFile "privatekey"

  let imported = Crypto.importFromBuffer contents :: Maybe Crypto.PrivateKey
  log $ maybe "Something went wrong" (sameKey private) imported
```


##### Generating a compressed Bitcoin address
```haskell
main = do
  { public } <- Crypto.generateKeyPair
  let ripemd  = public
              # Crypto.hash Crypto.SHA256
              # Crypto.hash Crypto.RIPEMD160

  let versionedHex = "00" <> (Crypto.toString ripemd)

  versioned <- Buffer.fromString versionedHex Encoding.Hex
  let checksum  = Crypto.hash Crypto.SHA256 versioned
                # Crypto.hash Crypto.SHA256
                # Crypto.toString
                # String.take 8

  let address = Crypto.baseEncode Crypto.BASE58 (versionedHex <> checksum)
  log $ maybe "Something went wrong" (\bAddr -> "BTC address: " <> Crypto.toString bAddr) address

  -- BTC address: 1BzasuqbvMibmh6bMsL8cMxue73uFUBsJ4
```


##### Encrypt/Decrypt with AES in CTR mode
```haskell
main = do
  { private } <- Crypto.generateKeyPair
  iv <- Crypto.generateInitializationVector
  msg <- Buffer.fromString "some msg to encrypt" Node.Encoding.UTF8
  encrypted <- Crypto.encryptCTR private iv msg
  log $ Crypto.toString encrypted
```

### Documentation

Module documentation is [published on Pursuit](http://pursuit.purescript.org/packages/purescript-simplecrypto).
