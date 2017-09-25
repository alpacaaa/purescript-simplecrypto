"use strict"

const crypto    = require("crypto")
const secp256k1 = require("secp256k1")
const baseX     = require("base-x")

exports.hashWith = function(algo) {
  return function(value) {
    return crypto
      .createHash(algo)
      .update(value)
      .digest("hex")
  }
}

const generatePrivateKey = function(bytes) {
  const privKey = crypto.randomBytes(bytes)
  if (secp256k1.privateKeyVerify(privKey)) {
    return privKey
  }

  return generatePrivateKey(bytes)
}

exports.createPrivateKey = function(bytes) {
  return function() {
    return generatePrivateKey(bytes)
  }
}

exports.derivePublicKey = function(privateKey) {
  return secp256k1.publicKeyCreate(privateKey)
}

exports.signFn = function(success) {
  return function(failure) {
    return function(privateKey) {
      return function(message) {
        try {
          const ret = secp256k1.sign(Buffer.from(message, "hex"), privateKey)
          return success(ret.signature)
        } catch (e) {
          return failure
        }
      }
    }
  }
}

exports.verify = function(publicKey) {
  return function(signature) {
    return function(message) {
      try {
        return secp256k1.verify(
          Buffer.from(message, "hex"),
          signature,
          publicKey
        )
      } catch (e) {
        return false
      }
    }
  }
}

const bufferToHex = function(buffer) {
  return buffer.toString("hex")
}

exports.bufferToHex = bufferToHex

exports.encodeWith = function(success) {
  return function(failure) {
    return function(encoding) {
      return function(value) {
        try {
          const ret = baseX(encoding).encode(Buffer.from(value, "hex"))
          return success(ret)
        } catch (e) {
          return failure
        }
      }
    }
  }
}

exports.decodeWith = function(success) {
  return function(failure) {
    return function(encoding) {
      return function(value) {
        try {
          const ret = baseX(encoding)
            .decode(value)
            .toString("hex")
          return success(ret)
        } catch (e) {
          return failure
        }
      }
    }
  }
}
