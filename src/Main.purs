module Main where

import Prelude
import Control.Monad.Eff (Eff)
import Control.Monad.Eff.Console (CONSOLE, log)

import Crypto.Simple as Crypto

main :: forall e. Eff (console :: CONSOLE | e) Unit
main = do
  let msg = Crypto.hash "some msg"

  pair <- Crypto.generateKeyPair

  let signature = Crypto.sign pair.private msg
  log ("Signature: " <> show signature)

  let verify = Crypto.verify pair.public signature msg
  log ("Signature valid: " <> show verify)
