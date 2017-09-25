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
  , KeyPair
  , Hash(..)
  , BaseEncoding(..)
  , EncodeData
  ) where

import Prelude
import Control.Monad.Eff (Eff)
import Data.Maybe (Maybe(..))

foreign import hashWith :: String -> String -> String
foreign import createPrivateKey :: forall e. Int -> Eff (e) PrivateKey
foreign import derivePublicKey :: PrivateKey -> PublicKey
foreign import signFn :: forall a. (a -> Maybe a) -> Maybe a -> PrivateKey -> String -> Maybe Signature
foreign import verify :: PublicKey -> Signature -> String -> Boolean
foreign import encodeWith :: forall a. (a -> Maybe a) -> Maybe a -> String -> String -> Maybe EncodeData
foreign import decodeWith :: forall a. (a -> Maybe a) -> Maybe a -> String -> EncodeData -> Maybe String
foreign import bufferToHex :: forall a. a -> String

data PrivateKey = PrivateKey
data PublicKey  = PublicKey
data Signature  = Signature
data EncodeData = EncodeData

type KeyPair = { private :: PrivateKey, public :: PublicKey }

data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

data BaseEncoding = BASE58

instance showPrivateKey :: Show PrivateKey where
  show = bufferToHex

instance showPublicKey :: Show PublicKey where
  show = bufferToHex

instance showSignature :: Show Signature where
  show = bufferToHex

instance showEncodeData :: Show EncodeData where
  show = bufferToHex

instance showHash :: Show Hash where
  show SHA1      = "sha1"
  show SHA256    = "sha256"
  show SHA512    = "sha512"
  show RIPEMD160 = "ripemd160"

instance showBaseEncoding :: Show BaseEncoding where
  show BASE58 = "base58"

generateKeyPair :: forall e. Eff (e) KeyPair
generateKeyPair = do
  private <- createPrivateKey 32
  let public = derivePublicKey private
  pure { private, public }

hash :: Hash -> String -> String
hash hashType content = hashWith (show hashType) content

sign :: PrivateKey -> String -> Maybe Signature
sign pk value = signFn Just Nothing pk value

baseEncode :: BaseEncoding -> String -> Maybe EncodeData
baseEncode encType content = encodeWith Just Nothing (baseAlphabet encType) content

baseDecode :: BaseEncoding -> EncodeData -> Maybe String
baseDecode encType encoded = decodeWith Just Nothing (baseAlphabet encType) encoded

baseAlphabet :: BaseEncoding -> String
baseAlphabet BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
