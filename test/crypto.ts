import tap from 'tap'
import * as bnc from '../src/index'

tap.test('signing', async (t) => {
  const privKey = bnc.generateSecret()
  const pubKey = bnc.derivePubKey(privKey)

  // These are examples of real life failed message/signatures
  const message = {
    address: '03d0715aa0b6f72fc09b048b4819e6fec86ab0fa1e43d1423e58e7aca89c150dc1',
    appId: "Snyder's Uke",
    data: {
      contents: "If you play too loud, those without calloused hands will be forced to hurt them."
    },
    destination: '039761e7a9967db6c70235c28f6d6b5f2e5c957d19b72984a8705ae0211ffcf513',
    id: '2c1cf6ee-7e1d-475e-82f5-62b9453fa668',
    signatures: [],
    ttl: 1,
    type: 'log'
  }

  // resign the message and check it out
  const sig = await bnc.sign(privKey, message)
  const ver = await bnc.verifySignature(message, sig, pubKey)

  t.ok(ver)

  t.end()
})

tap.test('encrypting', async (t) => {
  const priv = bnc.generateSecret()
  const pub = bnc.derivePubKey(priv)

  const dataObj = { encrypt: 'this!' }
  const dataStr = "encrypt this!"

  const encryptedObj = await bnc.encrypt(dataObj, pub)
  const decryptedObj = await bnc.decrypt(encryptedObj, priv)

  t.equal(decryptedObj.encrypt, dataObj.encrypt)

  const encryptedStr = await bnc.encrypt(dataStr, pub)
  const decryptedStr = await bnc.decrypt(encryptedStr, priv)

  t.equal(decryptedStr, dataStr)
})
