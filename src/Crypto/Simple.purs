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
foreign import createPrivateKey :: forall e. Int -> Eff (e) Node.Buffer
foreign import deriveKeyNative  :: Node.Buffer -> Node.Buffer
foreign import privateKeyExport :: PrivateKey -> Node.Buffer
foreign import privateKeyImport :: forall a. (PrivateKey -> Maybe PrivateKey) -> Maybe a -> Node.Buffer -> Maybe PrivateKey
foreign import signatureExport  :: Signature -> Node.Buffer
foreign import signatureImport  :: forall a. (Signature -> Maybe Signature) -> Maybe a -> Node.Buffer -> Maybe Signature
foreign import signFn           :: forall a. (Node.Buffer -> Maybe Node.Buffer) -> Maybe a -> Node.Buffer -> Node.Buffer -> Maybe Node.Buffer
foreign import verifyFn         :: Node.Buffer -> Node.Buffer -> Node.Buffer -> Boolean
foreign import encodeWith       :: forall a. (Node.Buffer -> Maybe Node.Buffer) -> Maybe a -> Alphabet -> String -> Maybe Node.Buffer
foreign import decodeWith       :: forall a. (String -> Maybe String) -> Maybe a -> Alphabet -> Node.Buffer -> Maybe String
foreign import bufferToHex      :: Node.Buffer -> String
foreign import verifyPrivateKey :: Node.Buffer -> Boolean
foreign import verifyPublicKey  :: Node.Buffer -> Boolean

data PrivateKey = PrivateKey Node.Buffer
data PublicKey  = PublicKey Node.Buffer
data Signature  = Signature Node.Buffer
data EncodeData = EncodeData Node.Buffer
data Digest     = Digest Node.Buffer

type KeyPair = { private :: PrivateKey, public :: PublicKey }


data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

data BaseEncoding = BASE58

newtype Alphabet = Alphabet String

newtype HashAlgorithm = HashAlgorithm String

eqBuffer :: Node.Buffer -> Node.Buffer -> Boolean
eqBuffer a b = (bufferToHex a) == (bufferToHex b)

instance eqPrivateKey :: Eq PrivateKey where
  eq (PrivateKey a) (PrivateKey b) = eqBuffer a b

instance eqPublicKey :: Eq PublicKey where
  eq (PublicKey a) (PublicKey b)   = eqBuffer a b

instance eqSignature :: Eq Signature where
  eq (Signature a) (Signature b)   = eqBuffer a b

instance eqEncodeData :: Eq EncodeData where
  eq (EncodeData a) (EncodeData b) = eqBuffer a b


class Serializable a where
  exportToBuffer   :: a -> Node.Buffer
  importFromBuffer :: Node.Buffer -> Maybe a
  toString         :: a -> String

importKey :: forall a. (Node.Buffer -> Boolean) -> (Node.Buffer -> a) -> Node.Buffer -> Maybe a
importKey verifier tagger buff =
  if verifier buff then
    Just (tagger buff)
  else
    Nothing

instance serializablePrivateKey :: Serializable PrivateKey where
  exportToBuffer (PrivateKey buff) = buff
  importFromBuffer                 = importKey verifyPrivateKey PrivateKey
  toString (PrivateKey buff)       = bufferToHex buff

instance serializablePublicKey :: Serializable PublicKey where
  exportToBuffer (PublicKey buff)  = buff
  importFromBuffer                 = importKey verifyPublicKey PublicKey
  toString (PublicKey buff)        = bufferToHex buff

instance serializableSignature :: Serializable Signature where
  exportToBuffer (Signature buff)  = buff
  importFromBuffer buff            = Just (Signature buff)
  toString (Signature buff)        = bufferToHex buff

instance serializableEncodeData :: Serializable EncodeData where
  exportToBuffer (EncodeData buff) = buff
  importFromBuffer buff            = Just (EncodeData buff)
  toString (EncodeData buff)       = bufferToHex buff

instance serializableDigest :: Serializable Digest where
  exportToBuffer (Digest buff) = buff
  importFromBuffer             = Just <<< Digest
  toString (Digest buff)       = bufferToHex buff

class Hashable a where
  hash :: Hash -> a -> Digest

hashBuffer :: forall a. (Serializable a) => Hash -> a -> Digest
hashBuffer hashType value =
  let
    buff = exportToBuffer value
    hash = hashBufferNative (hashToAlgo hashType) buff
  in
  Digest hash

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
  hash hashType buff =
    Digest $ hashBufferNative (hashToAlgo hashType) buff

generateKeyPair :: forall e. Eff (e) KeyPair
generateKeyPair = do
  key <- createPrivateKey 32
  let private = PrivateKey key
  let public  = derivePublicKey private

  pure { private, public }

derivePublicKey :: PrivateKey -> PublicKey
derivePublicKey (PrivateKey key) = PublicKey (deriveKeyNative key)

hashToAlgo :: Hash -> HashAlgorithm
hashToAlgo SHA1      = HashAlgorithm "sha1"
hashToAlgo SHA256    = HashAlgorithm "sha256"
hashToAlgo SHA512    = HashAlgorithm "sha512"
hashToAlgo RIPEMD160 = HashAlgorithm "ripemd160"

sign :: PrivateKey -> Digest -> Maybe Signature
sign (PrivateKey key) value = 
  let
    maybeBuff = signFn Just Nothing key (exportToBuffer value)
  in
  map Signature maybeBuff

verify :: PublicKey -> Signature -> Digest -> Boolean
verify (PublicKey key) (Signature signature) value =
  verifyFn key signature (exportToBuffer value)

baseEncode :: BaseEncoding -> String -> Maybe EncodeData
baseEncode encType content =
  let
    maybeBuff = encodeWith Just Nothing (baseAlphabet encType) content
  in
  map EncodeData maybeBuff

baseDecode :: BaseEncoding -> EncodeData -> Maybe String
baseDecode encType (EncodeData encoded) =
  decodeWith Just Nothing (baseAlphabet encType) encoded

baseAlphabet :: BaseEncoding -> Alphabet
baseAlphabet BASE58 = Alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"