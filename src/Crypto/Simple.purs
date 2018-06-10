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
  , encryptCTR
  , decryptCTR
  , generateInitializationVector
  , mkInitializationVector
  , Hash(..)
  , BaseEncoding(..)
  , PrivateKey
  , PublicKey
  , Signature
  , EncodeData
  , Digest
  , KeyPair
  , InitializationVector
  , EncryptedData(..)
  , CTRMode
  , class Serializable
  , class Hashable
  ) where

import Prelude
import Effect (Effect)
import Data.Maybe (Maybe(..))
import Node.Buffer (Buffer)

foreign import hashBufferNative :: HashAlgorithm -> Buffer -> Buffer
foreign import hashStringNative :: HashAlgorithm -> String -> Buffer
foreign import createPrivateKey :: Int -> Effect Buffer
foreign import deriveKeyNative  :: Buffer -> Buffer
foreign import privateKeyExport :: PrivateKey -> Buffer
foreign import privateKeyImport :: (PrivateKey -> Maybe PrivateKey) -> (forall a. Maybe a) -> Buffer -> Maybe PrivateKey
foreign import signatureExport  :: Signature -> Buffer
foreign import signatureImport  :: (Signature -> Maybe Signature) -> (forall a. Maybe a) -> Buffer -> Maybe Signature
foreign import signFn           :: (Buffer -> Maybe Buffer) -> (forall a. Maybe a) -> Buffer -> Buffer -> Maybe Buffer
foreign import verifyFn         :: Buffer -> Buffer -> Buffer -> Boolean
foreign import encodeWith       :: (Buffer -> Maybe Buffer) -> (forall a. Maybe a) -> Alphabet -> String -> Maybe Buffer
foreign import decodeWith       :: (String -> Maybe String) -> (forall a. Maybe a) -> Alphabet -> Buffer -> Maybe String
foreign import bufferToHex      :: Buffer -> String
foreign import verifyPrivateKey :: Buffer -> Boolean
foreign import verifyPublicKey  :: Buffer -> Boolean
foreign import nativeGenerateRandomNumber :: Effect Int

-- TODO Add failures
foreign import nativeAESEncrypt :: PrivateKey -> InitializationVector -> Buffer -> Effect Buffer
foreign import nativeAESDecrypt :: PrivateKey -> InitializationVector -> Buffer -> Effect Buffer

newtype PrivateKey = PrivateKey Buffer
newtype PublicKey  = PublicKey Buffer
newtype Signature  = Signature Buffer
newtype EncodeData = EncodeData Buffer
newtype Digest     = Digest Buffer

data EncryptedData algo = EncryptedData Buffer

type KeyPair = { private :: PrivateKey, public :: PublicKey }


data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

data ECBMode
data CBCMode
data CFBMode
data OFBMode
data CTRMode

data BaseEncoding = BASE58

newtype Alphabet = Alphabet String

newtype HashAlgorithm = HashAlgorithm String

newtype InitializationVector = InitializationVector Int

eqBuffer :: Buffer -> Buffer -> Boolean
eqBuffer a b = (bufferToHex a) == (bufferToHex b)

instance eqPrivateKey :: Eq PrivateKey where
  eq (PrivateKey a) (PrivateKey b) = eqBuffer a b

instance eqPublicKey :: Eq PublicKey where
  eq (PublicKey a) (PublicKey b)   = eqBuffer a b

instance eqSignature :: Eq Signature where
  eq (Signature a) (Signature b)   = eqBuffer a b

instance eqEncodeData :: Eq EncodeData where
  eq (EncodeData a) (EncodeData b) = eqBuffer a b

instance eqDigest :: Eq Digest where
  eq (Digest a) (Digest b) = eqBuffer a b

instance eqEncryptedData :: Eq (EncryptedData a) where
  eq (EncryptedData a) (EncryptedData b) = eqBuffer a b
  

class Serializable a where
  exportToBuffer   :: a -> Buffer
  importFromBuffer :: Buffer -> Maybe a
  toString         :: a -> String

importKey :: forall a. (Buffer -> Boolean) -> (Buffer -> a) -> Buffer -> Maybe a
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

instance serializableEncryptedData :: Serializable (EncryptedData a) where
  exportToBuffer (EncryptedData buff) = buff
  importFromBuffer                    = Just <<< EncryptedData
  toString (EncryptedData buff)       = bufferToHex buff

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

instance hashableBuffer :: Hashable Buffer where
  hash hashType buff =
    Digest $ hashBufferNative (hashToAlgo hashType) buff

generateKeyPair :: Effect KeyPair
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

generateInitializationVector :: Effect InitializationVector
generateInitializationVector =
  map InitializationVector nativeGenerateRandomNumber

mkInitializationVector :: Int -> Maybe InitializationVector
mkInitializationVector n
  | n > 0     = Just (InitializationVector n)
  | otherwise = Nothing

encryptCTR :: PrivateKey -> InitializationVector -> Buffer -> Effect (EncryptedData CTRMode)
encryptCTR pk iv payload = do
  encrypted <- nativeAESEncrypt pk iv payload
  pure (EncryptedData encrypted)

decryptCTR :: PrivateKey -> InitializationVector -> EncryptedData CTRMode -> Effect Buffer
decryptCTR pk iv (EncryptedData payload) =
  nativeAESDecrypt pk iv payload
