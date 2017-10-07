module Crypto.Simple
  ( hash
  , baseEncode
  , baseDecode
  , generateKeyPair
  , createPrivateKey
  , derivePublicKey
  , sign
  , verify
  , exportToBuffer
  , importFromBuffer
  , toString
  , Hash(..)
  , BaseEncoding(..)
  , PrivateKey
  , PublicKey
  , Signature
  , EncodeData
  , KeyPair
  , class Serialize
  ) where

import Prelude
import Control.Monad.Eff (Eff)
import Data.Maybe (Maybe(..))
import Node.Buffer as Node

foreign import hashWith         :: HashAlgorithm -> String -> String
foreign import createPrivateKey :: forall e. Int -> Eff (e) PrivateKey
foreign import derivePublicKey  :: PrivateKey -> PublicKey
foreign import privateKeyExport :: PrivateKey -> Node.Buffer
foreign import privateKeyImport :: forall a. (PrivateKey -> Maybe PrivateKey) -> Maybe a -> Node.Buffer -> Maybe PrivateKey
foreign import signatureExport  :: Signature -> Node.Buffer
foreign import signatureImport  :: forall a. (Signature -> Maybe Signature) -> Maybe a -> Node.Buffer -> Maybe Signature
foreign import signFn           :: forall a. (Signature -> Maybe Signature) -> Maybe a -> PrivateKey -> String -> Maybe Signature
foreign import verify           :: PublicKey -> Signature -> String -> Boolean
foreign import encodeWith       :: forall a. (EncodeData -> Maybe EncodeData) -> Maybe a -> Alphabet -> String -> Maybe EncodeData
foreign import decodeWith       :: forall a. (String -> Maybe String) -> Maybe a -> Alphabet -> EncodeData -> Maybe String
foreign import bufferToHex      :: forall a. a -> String
foreign import coerceBuffer     :: forall a b. a -> b

data PrivateKey
data PublicKey
data Signature
data EncodeData

type KeyPair = { private :: PrivateKey, public :: PublicKey }

data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

data BaseEncoding = BASE58

newtype Alphabet = Alphabet String

newtype HashAlgorithm = HashAlgorithm String

instance eqPrivateKey :: Eq PrivateKey where
  eq a b = (bufferToHex a) == (bufferToHex b)

instance eqPublicKey :: Eq PublicKey where
  eq a b = (bufferToHex a) == (bufferToHex b)

instance eqSignature :: Eq Signature where
  eq a b = (bufferToHex a) == (bufferToHex b)

instance eqEncodeData :: Eq EncodeData where
  eq a b = (bufferToHex a) == (bufferToHex b)

class Serialize a where
  exportToBuffer   :: a -> Node.Buffer
  importFromBuffer :: Node.Buffer -> Maybe a
  toString         :: a -> String

instance serializePrivateKey :: Serialize PrivateKey where
  exportToBuffer   = privateKeyExport
  importFromBuffer = privateKeyImport Just Nothing
  toString         = bufferToHex

instance serializePublicKey :: Serialize PublicKey where
  exportToBuffer buffer   = coerceBuffer buffer
  importFromBuffer buffer = Just (coerceBuffer buffer)
  toString                = bufferToHex

instance serializeSignature :: Serialize Signature where
  exportToBuffer   = signatureExport
  importFromBuffer = signatureImport Just Nothing
  toString         = bufferToHex

instance serializeEncodeData :: Serialize EncodeData where
  exportToBuffer buffer   = coerceBuffer buffer
  importFromBuffer buffer = Just (coerceBuffer buffer)
  toString                = bufferToHex

generateKeyPair :: forall e. Eff (e) KeyPair
generateKeyPair = do
  private <- createPrivateKey 32
  let public = derivePublicKey private
  pure { private, public }

hashToAlgo :: Hash -> HashAlgorithm
hashToAlgo SHA1      = HashAlgorithm "sha1"
hashToAlgo SHA256    = HashAlgorithm "sha256"
hashToAlgo SHA512    = HashAlgorithm "sha512"
hashToAlgo RIPEMD160 = HashAlgorithm "ripemd160"

hash :: Hash -> String -> String
hash hashType content = hashWith (hashToAlgo hashType) content

sign :: PrivateKey -> String -> Maybe Signature
sign pk value = signFn Just Nothing pk value

baseEncode :: BaseEncoding -> String -> Maybe EncodeData
baseEncode encType content = encodeWith Just Nothing (baseAlphabet encType) content

baseDecode :: BaseEncoding -> EncodeData -> Maybe String
baseDecode encType encoded = decodeWith Just Nothing (baseAlphabet encType) encoded

baseAlphabet :: BaseEncoding -> Alphabet
baseAlphabet BASE58 = Alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
