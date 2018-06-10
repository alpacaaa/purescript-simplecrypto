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


testCTRCommutative :: Effect Unit
testCTRCommutative = do
  let msg = "some msg"
  s <- Buffer.fromString msg Encoding.UTF8
  let gen = do
              pair <- Crypto.generateKeyPair
              iv <- Crypto.generateInitializationVector
              pure { key: pair.private, iv }

  fst <- gen
  snd <- gen

  encrypted <- Crypto.encryptCTR fst.key fst.iv s
  encryptedAgain <- Crypto.encryptCTR snd.key snd.iv (Crypto.exportToBuffer encrypted)

  decrypted <- Crypto.decryptCTR fst.key fst.iv encryptedAgain
  decryptedAgain <- Crypto.decryptCTR snd.key snd.iv (Crypto.EncryptedData decrypted)

  ret <- Buffer.toString Encoding.UTF8 decryptedAgain
  assert (msg == ret)


buffEq :: Buffer.Buffer -> Buffer.Buffer -> Effect Unit
buffEq a b = do
  s1 <- Buffer.toString Encoding.UTF8 a
  s2 <- Buffer.toString Encoding.UTF8 b
  assert (s1 == s2)

main :: Effect Unit
main = do
  let textMsg = "some msg"
      msg = Crypto.hash Crypto.SHA256 textMsg

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

  bufMsg <- Buffer.fromString textMsg Encoding.UTF8
  iv <- Crypto.generateInitializationVector
  encrypted <- Crypto.encryptCTR pair.private iv bufMsg
  assert (encrypted == importExportTest encrypted)

  decrypted <- Crypto.decryptCTR pair.private iv encrypted
  buffEq decrypted bufMsg

  -- CTR should be commutative
  testCTRCommutative
