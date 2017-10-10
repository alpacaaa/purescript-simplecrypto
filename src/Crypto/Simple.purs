module Crypto.Simple
  ( hash
  , generateKeyPair
  , createPrivateKey
  , derivePublicKey
  , sign
  , verify
  , exportToBuffer
  , importFromBuffer
  , toString
  , baseEncode
  , baseDecode
  , Hash(..)
  , BaseEncoding(..)
  , PrivateKey
  , PublicKey
  , Signature
  , EncodeData
  , Digest
  , KeyPair
  , class Serializable
  , class Hashable
  ) where

import Prelude
import Control.Monad.Eff (Eff)
import Data.Maybe (Maybe(..))
import Node.Buffer as Node

foreign import hashBufferNative :: HashAlgorithm -> Node.Buffer -> Node.Buffer
foreign import hashStringNative :: HashAlgorithm -> String -> Node.Buffer
foreign import createPrivateKey :: forall e. Int -> Eff (e) PrivateKey
foreign import derivePublicKey  :: PrivateKey -> PublicKey
foreign import privateKeyExport :: PrivateKey -> Node.Buffer
foreign import privateKeyImport :: forall a. (PrivateKey -> Maybe PrivateKey) -> Maybe a -> Node.Buffer -> Maybe PrivateKey
foreign import signatureExport  :: Signature -> Node.Buffer
foreign import signatureImport  :: forall a. (Signature -> Maybe Signature) -> Maybe a -> Node.Buffer -> Maybe Signature
foreign import signFn           :: forall a. (Signature -> Maybe Signature) -> Maybe a -> PrivateKey -> Node.Buffer -> Maybe Signature
foreign import verifyFn         :: PublicKey -> Signature -> Node.Buffer -> Boolean
foreign import encodeWith       :: forall a. (EncodeData -> Maybe EncodeData) -> Maybe a -> Alphabet -> String -> Maybe EncodeData
foreign import decodeWith       :: forall a. (String -> Maybe String) -> Maybe a -> Alphabet -> EncodeData -> Maybe String
foreign import bufferToHex      :: forall a. a -> String
foreign import coerceBuffer     :: forall a b. a -> b
foreign import verifyPrivateKey :: PrivateKey -> Boolean
foreign import verifyPublicKey  :: PublicKey -> Boolean

data PrivateKey
data PublicKey
data Signature
data EncodeData

type KeyPair = { private :: PrivateKey, public :: PublicKey }

data Digest = Digest Node.Buffer

data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

data BaseEncoding = BASE58

newtype Alphabet = Alphabet String

newtype HashAlgorithm = HashAlgorithm String

bufferEq :: forall a. (Serializable a) => a -> a -> Boolean
bufferEq a b = (bufferToHex a) == (bufferToHex b)

instance eqPrivateKey :: Eq PrivateKey where
  eq = bufferEq

instance eqPublicKey :: Eq PublicKey where
  eq = bufferEq

instance eqSignature :: Eq Signature where
  eq = bufferEq

instance eqEncodeData :: Eq EncodeData where
  eq = bufferEq

class Serializable a where
  exportToBuffer   :: a -> Node.Buffer
  importFromBuffer :: Node.Buffer -> Maybe a
  toString         :: a -> String

bufferToKey :: forall a. (a -> Boolean) -> Node.Buffer -> Maybe a
bufferToKey verifier buff =
  let
    key = coerceBuffer buff
  in
  if verifier key then Just key else Nothing

instance serializablePrivateKey :: Serializable PrivateKey where
  exportToBuffer   = coerceBuffer
  importFromBuffer = bufferToKey verifyPrivateKey
  toString         = bufferToHex

instance serializablePublicKey :: Serializable PublicKey where
  exportToBuffer   = coerceBuffer
  importFromBuffer = bufferToKey verifyPublicKey
  toString         = bufferToHex

instance serializableSignature :: Serializable Signature where
  exportToBuffer   = coerceBuffer
  importFromBuffer = Just <<< coerceBuffer
  toString         = bufferToHex

instance serializableEncodeData :: Serializable EncodeData where
  exportToBuffer   = coerceBuffer
  importFromBuffer = Just <<< coerceBuffer
  toString         = bufferToHex

instance serializableDigest :: Serializable Digest where
  exportToBuffer (Digest buff) = coerceBuffer buff
  importFromBuffer             = Just <<< Digest <<< coerceBuffer
  toString (Digest buff)       = bufferToHex buff

class Hashable a where
  hash :: Hash -> a -> Digest

hashBuffer :: forall a. (Serializable a) => Hash -> a -> Digest
hashBuffer hashType value =
  let
    buff = exportToBuffer value
    hash = hashBufferNative (hashToAlgo hashType) buff
  in Digest (coerceBuffer hash)

instance hashableString :: Hashable String where
  hash hashType value = Digest $ hashStringNative (hashToAlgo hashType) value

instance hashablePublicKey :: Hashable PublicKey where
  hash = hashBuffer

instance hashablePrivateKey :: Hashable PrivateKey where
  hash = hashBuffer

instance hashableSignature :: Hashable Signature where
  hash = hashBuffer

instance hashableEncodeData :: Hashable EncodeData where
  hash = hashBuffer

instance hashableDigest :: Hashable Digest where
  hash = hashBuffer

instance hashableBuffer :: Hashable Node.Buffer where
  hash hashType buff = Digest $ hashBufferNative (hashToAlgo hashType) buff

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

sign :: PrivateKey -> Digest -> Maybe Signature
sign pk value = signFn Just Nothing pk (exportToBuffer value)

verify :: PublicKey -> Signature -> Digest -> Boolean
verify key signature value = verifyFn key signature (exportToBuffer value)

baseEncode :: BaseEncoding -> String -> Maybe EncodeData
baseEncode encType content = encodeWith Just Nothing (baseAlphabet encType) content

baseDecode :: BaseEncoding -> EncodeData -> Maybe String
baseDecode encType encoded = decodeWith Just Nothing (baseAlphabet encType) encoded

baseAlphabet :: BaseEncoding -> Alphabet
baseAlphabet BASE58 = Alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"