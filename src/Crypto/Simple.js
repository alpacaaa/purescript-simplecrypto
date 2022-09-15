"use strict"

import baseX from 'base-x';
import secp256k1 from 'secp256k1';
import aesJs from 'aes-js';

const getBasex = lazyLoad(function() {
  return baseX;
  //return require("base-x")
})

const getSecp256k1 = lazyLoad(function() {
  return secp256k1;
  //return require("secp256k1")
})

const getAES = lazyLoad(function() {
  return aesJs;
  //return require("aes-js")
})

const hashBuffer = function(algo) {
  return function(value) {
    return crypto
      .createHash(algo)
      .update(value)
      .digest()
  }
}

export function hashBufferNative() { return hashBuffer.apply(this, arguments); };

export function hashStringNative() { return hashBuffer.apply(this, arguments); };

const generatePrivateKey = function(bytes) {
  const privateKey = crypto.randomBytes(bytes)
  if (getSecp256k1().privateKeyVerify(privateKey)) {
    return privateKey
  }

  return generatePrivateKey(bytes)
}

export function verifyPrivateKey(privateKey) {
  return getSecp256k1().privateKeyVerify(privateKey)
}

export function verifyPublicKey(publicKey) {
  return getSecp256k1().publicKeyVerify(publicKey)
}

export function createPrivateKey(bytes) {
  return function() {
    return generatePrivateKey(bytes)
  }
}

export function deriveKeyNative(privateKey) {
  return getSecp256k1().publicKeyCreate(privateKey, false)
}

export function privateKeyExport(privateKey) {
  return getSecp256k1().privateKeyExport(privateKey)
}

export function privateKeyImport(success) {
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

export function signFn(success) {
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

export function verifyFn(publicKey) {
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

export function signatureExport(signature) {
  return getSecp256k1().signatureExport(signature)
}

export function signatureImport(success) {
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

export function bufferToHex(buffer) {
  return buffer.toString("hex")
}

export function encodeWith(success) {
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

export function decodeWith(success) {
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

export function nativeAESEncrypt(privateKey) {
  return function(iv) {
    return function(payload) {
      return function() {
        var aesjs = getAES()
        var pk = aesjs.utils.hex.toBytes(privateKey.toString("hex"))
        var counter = new aesjs.Counter(iv)
        var instance = new aesjs.ModeOfOperation.ctr(pk, counter)
        return Buffer.from(instance.encrypt(payload))
      }
    }
  }
}

export function nativeAESDecrypt(privateKey) {
  return function(iv) {
    return function(payload) {
      return function() {
        var aesjs = getAES()
        var pk = aesjs.utils.hex.toBytes(privateKey.toString("hex"))
        var counter = new aesjs.Counter(iv)
        var instance = new aesjs.ModeOfOperation.ctr(pk, counter)
        return Buffer.from(instance.decrypt(payload))
      }
    }
  }
}

export function nativeGenerateRandomNumber() {
  return crypto.randomBytes(8).readUInt32BE()
}
