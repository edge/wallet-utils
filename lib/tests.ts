import * as lib from '.'
import assert from 'assert'

const testWallets = [
  {
    address:    'xe_61db6997734714592fa3524Ee39a118A412Aaf0E',
    privateKey: '77899554d233356bb0d911a64d75e200dc6387f8568c4f26b9c14a4bfacb2a4f',
    publicKey:  '035f4fe9c44a5fdf49746a8a3b613a8cc0233d7c08887c03b228079831a71782d6'
  },
  {
    address:    'xe_83864063Aa989c64530cC162906aC0ed4Ffa0d67',
    privateKey: '497f28f699fbb659d402c800a79e03f8a68a04984c210171c0802fd0e43ad233',
    publicKey:  '03e11f086ea6ff921cc611a45d42223c5b29c9ebd99b726e3b7d12824bf9a58ac9'
  },
  {
    address:    'xe_e4a88b743A79078984176B5FCba0F81bc7888fFc',
    privateKey: '02c466d756cda407ea7268753ac984c63a7365828c5a5f1caaac374ef710126f',
    publicKey:  '0367b7c72ee842ae3cd1af6b139586c93d7906f72a81610116a5331bd3823d78b8'
  }
]

const runTests = (...fs: (() => void)[]): void => {
  let ok = true
  fs.forEach(f => {
    try {
      f()
    }
    catch (err) {
      ok = false
      console.debug(err)
    }
  })
  if (!ok) process.exit(1)
}

const testChecksumAddressIsValid = () => {
  testWallets.forEach(wallet => {
    assert.ok(lib.checksumAddressIsValid(wallet.address))
  })
}

const testPublicKeyToChecksumAddress = () => {
  testWallets.forEach(wallet => {
    assert.strictEqual(lib.publicKeyToChecksumAddress(wallet.publicKey), wallet.address)
  })
}

const testPrivateKeyToPublicKey = () => {
  testWallets.forEach(wallet => {
    assert.strictEqual(lib.privateKeyToPublicKey(wallet.privateKey), wallet.publicKey)
  })
}

const testPrivateKeyToChecksumAddress = () => {
  testWallets.forEach(wallet => {
    assert.strictEqual(lib.privateKeyToChecksumAddress(wallet.privateKey), wallet.address)
  })
}

runTests(
  testChecksumAddressIsValid,
  testPublicKeyToChecksumAddress,
  testPrivateKeyToPublicKey,
  testPrivateKeyToChecksumAddress
)
