module Test.Main where

import Prelude
import Control.Monad.Eff (Eff)
import Control.Monad.Eff.Console (CONSOLE, log)
import Test.Assert (assert, ASSERT)

import Crypto.Simple as Crypto

foreign import stringLength :: String -> Int -- really?

len :: forall a. Show a => a -> Int
len = stringLength <<< show

main :: forall e. Eff (console :: CONSOLE, assert :: ASSERT | e) Unit
main = do
  let msg = Crypto.hash Crypto.SHA256 "some msg"
  assert (stringLength msg == 64)

  pair <- Crypto.generateKeyPair
  assert (len pair.private == 64)

  let signature = Crypto.sign pair.private msg
  log ("Signature: " <> show signature)

  let verify = Crypto.verify pair.public signature msg
  log ("Signature valid: " <> show verify)
  assert (verify == true)
