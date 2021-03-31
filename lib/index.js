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

const words = require('./words')
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
  const phrase = phraseFromPrivateKey(privateKey)
  return { privateKey, publicKey, address, phrase }
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
function phraseFromPrivateKey(privateKey) {
  const key = `${privateKey}00`
  const triplets = key.match(/.{1,3}/g)
  return triplets.map(triplet => words[parseInt(triplet, 16)]).join(' ')
}

function privateKeyFromPhrase(phrase) {
  const chunks = phrase.split(' ')
  const triplets = chunks.map(chunk => words.indexOf(chunk).toString(16).padStart(3, '0'))
  return triplets.join('').slice(0, -2)
}

function publicKeyToChecksumAddress(publicKey) {
  const hash = keccak256(publicKey)
  const addr = 'xe_' + hash.substring(hash.length - 40, hash.length)
  return generateChecksumAddress(addr)
}

function privateKeyToPublicKey(privateKey) {
  return ec.keyFromPrivate(privateKey, 'hex').getPublic(true, 'hex')
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

module.exports = {
  generateKeyPair,
  generateWallet,
  generateChecksumAddress,
  checksumAddressIsValid,
  phraseFromPrivateKey,
  privateKeyFromPhrase,
  publicKeyToChecksumAddress,
  privateKeyToPublicKey,
  generateSignature,
  verifySignatureAddress,
  recoverPublicKeyFromSignedMessage,
  words
}
