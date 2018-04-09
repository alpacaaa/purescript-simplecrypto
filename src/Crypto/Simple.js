"use strict"

const crypto = require("crypto")

const getBasex = lazyLoad(function() {
  return require("base-x")
})

const getSecp256k1 = lazyLoad(function() {
  return require("secp256k1")
})

const hashBuffer = function(algo) {
  return function(value) {
    return crypto
      .createHash(algo)
      .update(value)
      .digest()
  }
}

exports.hashBufferNative = hashBuffer

exports.hashStringNative = hashBuffer

const generatePrivateKey = function(bytes) {
  const privateKey = crypto.randomBytes(bytes)
  if (getSecp256k1().privateKeyVerify(privateKey)) {
    return privateKey
  }

  return generatePrivateKey(bytes)
}

exports.verifyPrivateKey = function(privateKey) {
  return getSecp256k1().privateKeyVerify(privateKey)
}

exports.verifyPublicKey = function(publicKey) {
  return getSecp256k1().publicKeyVerify(publicKey)
}

exports.createPrivateKey = function(bytes) {
  return function() {
    return generatePrivateKey(bytes)
  }
}

exports.deriveKeyNative = function(privateKey) {
  return getSecp256k1().publicKeyCreate(privateKey, false)
}

exports.privateKeyExport = function(privateKey) {
  return getSecp256k1().privateKeyExport(privateKey)
}

exports.privateKeyImport = function(success) {
  return function(failure) {
    return function(buffer) {
      try {
        const ret = getSecp256k1().privateKeyImport(buffer)
        return success(ret)
      } catch (e) {
        return failure
      }
    }
  }
}

exports.signFn = function(success) {
  return function(failure) {
    return function(privateKey) {
      return function(message) {
        try {
          const ret = getSecp256k1().sign(
            message,
            privateKey
          )
          return success(ret.signature)
        } catch (e) {
          return failure
        }
      }
    }
  }
}

exports.verifyFn = function(publicKey) {
  return function(signature) {
    return function(message) {
      try {
        return getSecp256k1().verify(
          message,
          signature,
          publicKey
        )
      } catch (e) {
        return false
      }
    }
  }
}

exports.signatureExport = function(signature) {
  return getSecp256k1().signatureExport(signature)
}

exports.signatureImport = function(success) {
  return function(failure) {
    return function(buffer) {
      try {
        const ret = getSecp256k1().signatureImport(buffer)
        return success(ret)
      } catch (e) {
        return failure
      }
    }
  }
}

exports.bufferToHex = function(buffer) {
  return buffer.toString("hex")
}

exports.bufferFromHex = function(string) {
  return Buffer.from(string, "hex")
}

exports.encodeWith = function(success) {
  return function(failure) {
    return function(encoding) {
      return function(value) {
        try {
          const ret = getBasex()(encoding).encode(Buffer.from(value, "hex"))
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
          const ret = getBasex()(encoding)
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

// dirty trick to lazy load dependencies
function lazyLoad(loadPkg) {
  var fn = function() {
    const loaded = loadPkg()
    fn = function() {
      return loaded
    }

    return fn()
  }

  return fn
}
