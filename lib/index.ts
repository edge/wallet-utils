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

import SHA256 from 'crypto-js/sha256'
import elliptic from 'elliptic'
import { keccak256 } from 'js-sha3'

type Address = string
type ChecksumAddress = Address
type Message = string
type PrivateKey = Uint8Array | Buffer | string | number[] | elliptic.ec.KeyPair
type PublicKey = string
type SigningPrivateKey = Buffer | elliptic.ec.KeyPair
type Signature = string

type Wallet = {
  address: Address
  privateKey: PrivateKey
  publicKey: PublicKey
}

const ec = new elliptic.ec('secp256k1')

//
// Key/account generation
//
function generateKeyPair() {
  return ec.genKeyPair()
}

export function generateWallet(): Wallet {
  const keyPair = generateKeyPair()
  const privateKey = keyPair.getPrivate('hex').toString()
  const publicKey = keyPair.getPublic(true, 'hex').toString()
  const address = publicKeyToChecksumAddress(publicKey)
  return { privateKey, publicKey, address }
}

export function generateChecksumAddress(address: Address): ChecksumAddress {
  const addr = address.slice(3)
  const addrHash = keccak256(addr.toLowerCase())

  let chkAddr = ''
  for (let i = 0; i < addr.length; i++) {
    if (parseInt(addrHash[i], 16) >= 8) chkAddr += addr[i].toUpperCase()
    else chkAddr += addr[i]
  }

  return `xe_${chkAddr}`
}

export function checksumAddressIsValid(address: Address): boolean {
  if (!/^(xe_[a-fA-F0-9]{40})$/.test(address)) return false
  if (address !== generateChecksumAddress(address)) return false
  return true
}

//
// Conversion
//
export function publicKeyToChecksumAddress(publicKey: PublicKey): ChecksumAddress {
  const hash = keccak256(publicKey)
  const addr = 'xe_' + hash.substring(hash.length - 40, hash.length)
  return generateChecksumAddress(addr)
}

export function privateKeyToPublicKey(privateKey: PrivateKey): PublicKey {
  return ec.keyFromPrivate(privateKey, 'hex').getPublic(true, 'hex')
}

export function privateKeyToChecksumAddress(privateKey: PrivateKey): ChecksumAddress {
  const publicKey = privateKeyToPublicKey(privateKey)
  return publicKeyToChecksumAddress(publicKey)
}

export function xeStringFromMicroXe(mxe: number, format: boolean): string {
  const s = mxe.toString()
  const fraction = s.substr(-6, 6).padStart(6, '0')
  let whole = s.substr(0, s.length - 6) || '0'
  if (format) whole = parseInt(whole).toLocaleString('en-US')
  return `${whole}.${fraction}`
}

export function toMicroXe(xe: string|number): number {
  const s = typeof xe === 'number' ? xe.toString() : xe
  const parts = s.split('.')
  const whole = parts[0]
  const fraction = parts.length > 1 ? parts[1].padEnd(6, '0') : '000000'
  return parseInt(`${whole}${fraction}`)
}

export function formatXe(xe: string|number, format: boolean): string {
  const mxe = toMicroXe(xe)
  return xeStringFromMicroXe(mxe, format)
}

//
// Signatures
//
export function generateSignature(privateKey: SigningPrivateKey, msg: Message): Signature {
  const msgHash = SHA256(msg).toString()
  const msgHashByteArray = elliptic.utils.toArray(msgHash, 'hex')
  const signatureObj = ec.sign(msgHashByteArray, privateKey, 'hex', { canonical: true })
  const r = signatureObj.r.toString('hex', 32)
  const s = signatureObj.s.toString('hex', 32)
  const i = (typeof signatureObj.recoveryParam === 'number')
    ? signatureObj.recoveryParam.toString(16).padStart(2, '0')
    : ''
  return r + s + i
}

export function verifySignatureAddress(msg: string, signature: Signature, address: Address): boolean {
  const publicKey = recoverPublicKeyFromSignedMessage(msg, signature)
  const derivedAddress = publicKeyToChecksumAddress(publicKey)
  return address === derivedAddress
}

export function recoverPublicKeyFromSignedMessage(msg: Message, signature: Signature): PublicKey {
  const signatureObj = { r: signature.slice(0, 64), s: signature.slice(64, 128) }
  const recoveryParam = parseInt(signature.slice(128, 130), 16)
  const msgHash = SHA256(msg).toString()
  const msgHashByteArray = elliptic.utils.toArray(msgHash, 'hex')
  const publicKey = ec.recoverPubKey(msgHashByteArray, signatureObj, recoveryParam, 'hex')
  return publicKey.encode('hex', true)
}

export function recoverAddressFromSignedMessage(msg: Message, signature: Signature): Address {
  const publicKey = recoverPublicKeyFromSignedMessage(msg, signature)
  const derivedAddress = publicKeyToChecksumAddress(publicKey)
  return derivedAddress
}
