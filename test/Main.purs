module Test.Main where

import Prelude

import Effect (Effect)
import Effect.Console (log)
import Crypto.Simple as Crypto
import Data.Maybe (Maybe, fromJust)
import Data.String as String
import Node.Buffer as Buffer
import Node.Encoding as Encoding
import Partial.Unsafe (unsafePartial)
import Test.Assert (assert)

hashLength :: forall a. (Crypto.Serializable a) => a -> Int
hashLength = String.length <<< Crypto.toString

try :: forall a. Maybe a -> a
try a = unsafePartial $ fromJust a

importExportTest :: forall a. (Crypto.Serializable a) => a -> a
importExportTest value =
  let
    exported = Crypto.exportToBuffer value
  in
  try (Crypto.importFromBuffer exported)

btcAddressTest :: String -> Effect String
btcAddressTest key = do
  buff <- Buffer.fromString key Encoding.Hex
  let private = try (Crypto.importFromBuffer buff) :: Crypto.PrivateKey
  let ripemd  = Crypto.derivePublicKey private
              # Crypto.hash Crypto.SHA256
              # Crypto.hash Crypto.RIPEMD160

  let versionedHex = "00" <> (Crypto.toString ripemd)

  versioned <- Buffer.fromString versionedHex Encoding.Hex
  let checksum  = Crypto.hash Crypto.SHA256 versioned
                # Crypto.hash Crypto.SHA256
                # Crypto.toString
                # String.take 8

  let address = try $ Crypto.baseEncode Crypto.BASE58 (versionedHex <> checksum)
  pure (Crypto.toString address)


main :: Effect Unit
main = do
  let msg = Crypto.hash Crypto.SHA256 "some msg"
  assert (hashLength msg == 64)

  pair <- Crypto.generateKeyPair
  assert $ (hashLength pair.private) == 64

  assert (pair.private == importExportTest pair.private)
  assert (pair.public == importExportTest pair.public)

  let signature = try (Crypto.sign pair.private msg)
  log ("Signature: " <> Crypto.toString signature)

  let verify = Crypto.verify pair.public signature msg
  assert (verify == true)

  assert (signature == importExportTest signature)

  let encoded = try $ Crypto.baseEncode Crypto.BASE58 (Crypto.toString msg)
  log ("Encoded base58: " <> Crypto.toString encoded)

  assert (encoded == importExportTest encoded)

  let decoded = try (Crypto.baseDecode Crypto.BASE58 encoded)
  assert (decoded == Crypto.toString msg)

  address <- btcAddressTest "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
  log ("BTC address: " <> address)
  assert (address == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")

  let iv = Crypto.InitializationVector 1
      aesMsg = "la merda rosa"

  encrypted <- Crypto.ctrEncode pair.private iv aesMsg
  decrypted <- Crypto.ctrDecode pair.private iv encrypted
  assert (decrypted == aesMsg)
