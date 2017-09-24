module Crypto.Simple
  ( generateKeyPair
  , hash
  , sign
  , verify
  , createPrivateKey
  , derivePublicKey
  , PrivateKey
  , PublicKey
  , Signature
  , Key
  , KeyPair
  , Hash(..)
  ) where

import Prelude
import Control.Monad.Eff (Eff)

foreign import data KeyData :: Type
foreign import hashWith :: String -> String -> String
foreign import createPrivateKey :: forall e. Int -> Eff (e) (Key PrivateKey)
foreign import derivePublicKey :: (Key PrivateKey) -> (Key PublicKey)
foreign import sign :: (Key PrivateKey) -> String -> Signature
foreign import verify :: (Key PublicKey) -> Signature -> String -> Boolean
foreign import keyToString :: forall a. Key a -> String
foreign import sigToString :: Signature -> String

data PrivateKey
data PublicKey
data Signature
data Key a = Key KeyData

type KeyPair = { private :: Key PrivateKey, public :: Key PublicKey }

data Hash = SHA1 | SHA256 | SHA512 | RIPEMD160

instance showKey :: Show (Key a) where
  show = keyToString

instance showSignature :: Show Signature where
  show = sigToString

instance showHash :: Show Hash where
  show SHA1      = "sha1"
  show SHA256    = "sha256"
  show SHA512    = "sha512"
  show RIPEMD160 = "ripemd160"

generateKeyPair :: forall e. Eff (e) KeyPair
generateKeyPair = do
  private <- createPrivateKey 32
  let public = derivePublicKey private
  pure { private, public }

hash :: Hash -> String -> String
hash hashType content = hashWith (show hashType) content
