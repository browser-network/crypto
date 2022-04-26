import { createHash } from 'crypto'
import * as eccrypto from 'eccrypto'

// Buffer to string. eccrypto uses buffers for everything but we want to use strings.
// This is to convert.
export const btos = (buffer: Buffer): string => buffer.toString('hex')

// String to buffer. Takes a string, like a key, and turns it into a buffer that
// eccrypto can use.
export const stob = (str: string): Buffer => Buffer.from(str, 'hex')

// Generate a hash of any arbitrary data, so long as it's JSON stringifiable.
export const hash = (data: any) => createHash('sha256').update(JSON.stringify(data)).digest()

// Take an object and create a signature for it based on a given private key.
export const sign = async <T>(secret: string, obj: T): Promise<string> => {
  const stringState = JSON.stringify(obj)
  const hashBuff    = hash(stringState)
  const keyBuff     = stob(secret) as Buffer

  const sigBuff = await eccrypto.sign(keyBuff, hashBuff)
  const signature = btos(sigBuff)

  return signature
}

// Take an object, signature and pub key, and ensure that the signature matches the object
// given the public key.
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

// Derive an EC public key from a given private key.
export const derivePubKey = (secret: string): string => {
  return btos(eccrypto.getPublicCompressed(stob(secret)))
}

// Generate the type of private key that network uses for its
// cryptography. Generating one of these is as good as creating a new identity
// on the network.
export const generateSecret = (): string => {
  const privBuf = eccrypto.generatePrivate()
  return btos(privBuf)
}

// TODO encrypt, decrypt, diffie helman
