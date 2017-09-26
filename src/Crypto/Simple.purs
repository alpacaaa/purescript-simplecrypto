module Crypto.Simple
  ( generateKeyPair
  , hash
  , sign
  , verify
  , baseEncode
  , baseDecode
  , createPrivateKey
  , derivePublicKey
  , PrivateKey
  , PublicKey
  , Signature
  , EncodeData
  , KeyPair
  , Hash(..)
  , BaseEncoding(..)
  ) where

import Prelude
import Control.Monad.Eff (Eff)
import Data.Maybe (Maybe(..))

foreign import hashWith         :: HashAlgorithm -> String -> String
foreign import createPrivateKey :: forall e. Int -> Eff (e) PrivateKey
foreign import derivePublicKey  :: PrivateKey -> PublicKey
foreign import signFn           :: forall a. (Signature -> Maybe Signature) -> Maybe a -> PrivateKey -> String -> Maybe Signature
foreign import verify           :: PublicKey -> Signature -> String -> Boolean
foreign import encodeWith       :: forall a. (EncodeData -> Maybe EncodeData) -> Maybe a -> Alphabet -> String -> Maybe EncodeData
foreign import decodeWith       :: forall a. (String -> Maybe String) -> Maybe a -> Alphabet -> EncodeData -> Maybe String
foreign import bufferToHex      :: forall a. a -> String

data PrivateKey
data PublicKey
data Signature
data EncodeData

type KeyPair = { private :: PrivateKey, public :: PublicKey }

data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

data BaseEncoding = BASE58

newtype Alphabet = Alphabet String

newtype HashAlgorithm = HashAlgorithm String

instance showPrivateKey :: Show PrivateKey where
  show = bufferToHex

instance showPublicKey :: Show PublicKey where
  show = bufferToHex

instance showSignature :: Show Signature where
  show = bufferToHex

instance showEncodeData :: Show EncodeData where
  show = bufferToHex


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
