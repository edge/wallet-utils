//                  $$\
//                  $$ |
//   $$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$\
//  $$  __$$\ $$  __$$ |$$  __$$\ $$  __$$\
//  $$$$$$$$ |$$ /  $$ |$$ /  $$ |$$$$$$$$ |
//  $$   ____|$$ |  $$ |$$ |  $$ |$$   ____|
//  \$$$$$$$\ \$$$$$$$ |\$$$$$$$ |\$$$$$$$\
//   \_______| \_______| \____$$ | \_______|
//                      $$\   $$ |
// © 2021 Edge Network  \$$$$$$  |
//   Technologies Ltd.   \______/

const SHA256 = require('crypto-js/sha256')
const keccak256 = require('js-sha3').keccak256
const elliptic = require('elliptic')
const ec = new elliptic.ec('secp256k1')

//
// Key/account generation
//
function generateKeyPair() {
  return ec.genKeyPair()
}

function generateWallet() {
  const keyPair = generateKeyPair()
  const privateKey = keyPair.getPrivate('hex').toString()
  const publicKey = keyPair.getPublic(true, 'hex').toString()
  const address = publicKeyToChecksumAddress(publicKey)
  return { privateKey, publicKey, address }
}

function generateChecksumAddress(address) {
  const addr = address.slice(3)
  const addrHash = keccak256(addr.toLowerCase())

  let chkAddr = ''
  for (let i = 0; i < addr.length; i++) {
    if (parseInt(addrHash[i], 16) >= 8) chkAddr += addr[i].toUpperCase()
    else chkAddr += addr[i]
  }

  return `xe_${chkAddr}`
}

function checksumAddressIsValid(address) {
  if (address.length !== 43) return false
  if (address.substr(0, 3) !== 'xe_') return false
  if (address !== generateChecksumAddress(address)) return false
  return true
}

//
// Conversion
//
function publicKeyToChecksumAddress(publicKey) {
  const hash = keccak256(publicKey)
  const addr = 'xe_' + hash.substring(hash.length - 40, hash.length)
  return generateChecksumAddress(addr)
}

function privateKeyToPublicKey(privateKey) {
  return ec.keyFromPrivate(privateKey, 'hex').getPublic(true, 'hex')
}

function privateKeyToChecksumAddress(privateKey) {
  const publicKey = privateKeyToPublicKey(privateKey)
  return publicKeyToChecksumAddress(publicKey)
}

function xeStringFromMicroXe(mxe, format) {
  const s = mxe.toString()
  const fraction = s.substr(-6, 6).padStart(6, '0')
  let whole = s.substr(0, s.length - 6) || '0'
  if (format) whole = parseInt(whole).toLocaleString('en-US')
  return `${whole}.${fraction}`
}

function toMicroXe(xe) {
  const s = typeof xe === 'number' ? xe.toString() : xe
  const parts = s.split('.')
  const whole = parts[0]
  const fraction = parts.length > 1 ? parts[1].padEnd(6, '0') : '000000'
  return parseInt(`${whole}${fraction}`)
}

//
// Signatures
//
function generateSignature(privateKey, msg) {
  const msgHash = SHA256(msg).toString()
  const msgHashByteArray = elliptic.utils.toArray(msgHash, 'hex')
  const signatureObj = ec.sign(msgHashByteArray, privateKey, 'hex', { canonical: true })
  const r = signatureObj.r.toString('hex', 32)
  const s = signatureObj.s.toString('hex', 32)
  const i = signatureObj.recoveryParam.toString(16).padStart(2, '0')
  return r + s + i
}

function verifySignatureAddress(msg, signature, address) {
  const publicKey = recoverPublicKeyFromSignedMessage(msg, signature)
  const derivedAddress = publicKeyToChecksumAddress(publicKey)
  return address === derivedAddress
}

function recoverPublicKeyFromSignedMessage(msg, signature) {
  const signatureObj = { r: signature.slice(0, 64), s: signature.slice(64, 128) }
  const recoveryParam = parseInt(signature.slice(128, 130), 16)
  const msgHash = SHA256(msg).toString()
  const msgHashByteArray = elliptic.utils.toArray(msgHash, 'hex')
  const publicKey = ec.recoverPubKey(msgHashByteArray, signatureObj, recoveryParam, 'hex')
  return publicKey.encode('hex', true)
}

function recoverAddressFromSignedMessage(msg, signature) {
  const publicKey = recoverPublicKeyFromSignedMessage(msg, signature)
  const derivedAddress = publicKeyToChecksumAddress(publicKey)
  return derivedAddress
}

module.exports = {
  generateKeyPair,
  generateWallet,
  generateChecksumAddress,
  checksumAddressIsValid,
  publicKeyToChecksumAddress,
  privateKeyToChecksumAddress,
  privateKeyToPublicKey,
  generateSignature,
  verifySignatureAddress,
  recoverPublicKeyFromSignedMessage,
  recoverAddressFromSignedMessage,
  xeStringFromMicroXe,
  toMicroXe
}
