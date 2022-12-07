import { createHash } from 'crypto'
import * as eccrypto from 'eccrypto'

/**
* @description Buffer to string -- eccrypto uses buffers for everything, and converting them to strings
* makes it easier to use
*/
export const btos = (buffer: Buffer): string => buffer.toString('hex')

/**
* @description String to buffer. Takes a string, like a key, and turns it into a buffer that
* eccrypto can use
*/
export const stob = (str: string): Buffer => Buffer.from(str, 'hex')

/**
* @description Generate a hash of any arbitrary data, so long as it's JSON stringifiable
*/
export const hash = (data: any) => createHash('sha256').update(JSON.stringify(data)).digest()

/**
* @description Take an object and create a signature for it based on a given private key
*/
export const sign = async (secret: string, obj: any): Promise<string> => {
  const stringState = JSON.stringify(obj)
  const hashBuff    = hash(stringState)
  const keyBuff     = stob(secret) as Buffer

  const sigBuff = await eccrypto.sign(keyBuff, hashBuff)
  const signature = btos(sigBuff)

  return signature
}

/**
* @description Take an object, signature and pub key, and ensure that the signature matches the object
* given the public key
*/
export const verifySignature = async (object: any, signature: string, publicKey: string): Promise<boolean> => {
  const stringObj = JSON.stringify(object)
  const hashBuf   = hash(stringObj)
  const pubBuf    = stob(publicKey)
  const sigBuf    = stob(signature)

  try {
    await eccrypto.verify(pubBuf, hashBuf, sigBuf)
    return true
  } catch (e) {
    return false
  }
}

/**
* @description Derive an EC public key from a given private key
*/
export const derivePubKey = (secret: string): string => {
  return btos(eccrypto.getPublicCompressed(stob(secret)))
}

/**
* @description Generate a new ellyptic curve private key
*/
export const generateSecret = (): string => {
  const privBuf = eccrypto.generatePrivate()
  return btos(privBuf)
}

/**
* @description Take some data and encrypt it for the supplied public key. The
* owner of that public key, with their associated private key, will be able to
* decrypt the data
*/
export const encrypt = async (data: any, toPubKey: string): Promise<string> => {
  const bufPub = stob(toPubKey)
  const strDat = JSON.stringify(data)
  const bufDat = Buffer.from(strDat) // won't work with hex for some reason

  const resp = await eccrypto.encrypt(bufPub, bufDat)

  // The response here consists of a series of fields that produce an ecies message.
  // Each field is a buffer, and we want to string them all up for transport.
  // JSON.stringify-ing the whole thing and the parsing it results in a different
  // object, so we go piecewise.
  for (const key in resp) {
    resp[key] = btos(resp[key])
  }

  return JSON.stringify(resp)
}

/**
* @description Take a stringified, encrypted message, as produced by bnc.encrypt, and
* decrypt it using the private key of the associated public key the message was produced
* for
*/
export const decrypt = async (message: string, privKey: string): Promise<any> => {
  const bufPriv = stob(privKey)
  const eciesMessage = JSON.parse(message)

  // Re-bufferize each field, see note in `encrypt`
  for (const key in eciesMessage) {
    eciesMessage[key] = stob(eciesMessage[key])
  }

  const resp = await eccrypto.decrypt(bufPriv, eciesMessage)
  const unbuffed = resp.toString()
  return JSON.parse(unbuffed)
}

// TODO diffie helman
