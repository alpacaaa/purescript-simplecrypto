module Test.Main where

import Prelude
import Control.Monad.Eff (Eff)
import Control.Monad.Eff.Console (CONSOLE, log)
import Data.Maybe (Maybe, fromJust)
import Partial.Unsafe (unsafePartial)
import Test.Assert (assert, ASSERT)

import Crypto.Simple as Crypto

foreign import stringLength :: String -> Int -- really?

len :: forall a. Show a => a -> Int
len = stringLength <<< show

btcAddress :: Crypto.PublicKey -> Maybe Crypto.EncodeData
btcAddress pk = show pk
  # Crypto.hash Crypto.SHA256
  # Crypto.hash Crypto.SHA256
  # Crypto.hash Crypto.RIPEMD160
  # Crypto.baseEncode Crypto.BASE58

main :: forall e. Eff (console :: CONSOLE, assert :: ASSERT | e) Unit
main = do
  let msg = Crypto.hash Crypto.SHA256 "some msg"
  assert (stringLength msg == 64)

  pair <- Crypto.generateKeyPair
  assert (len pair.private == 64)

  let signature = unsafePartial $ fromJust $ Crypto.sign pair.private msg
  log ("Signature: " <> show signature)

  let verify = Crypto.verify pair.public signature msg
  log ("Signature valid: " <> show verify)
  assert (verify == true)

  let encoded = unsafePartial $ fromJust $ Crypto.baseEncode Crypto.BASE58 msg
  log ("Encoded base58: " <> show encoded)

  let decoded = unsafePartial $ fromJust $ Crypto.baseDecode Crypto.BASE58 encoded
  assert (decoded == msg)

  let address = unsafePartial $ fromJust $ btcAddress pair.public
  log ("BTC address: " <> show address)
