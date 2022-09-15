{ name = "purescript-simplecrypto"
, dependencies =
  [
    "effect"
  , "maybe"
  , "node-buffer"
  , "prelude"
, ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs" ]
}
