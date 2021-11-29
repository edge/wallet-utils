"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
exports.recoverAddressFromSignedMessage = exports.recoverPublicKeyFromSignedMessage = exports.verifySignatureAddress = exports.generateSignature = exports.formatXe = exports.toMicroXe = exports.xeStringFromMicroXe = exports.privateKeyToChecksumAddress = exports.privateKeyToPublicKey = exports.publicKeyToChecksumAddress = exports.checksumAddressIsValid = exports.generateChecksumAddress = exports.generateWallet = exports.generateKeyPair = void 0;
var sha256_1 = __importDefault(require("crypto-js/sha256"));
var elliptic_1 = __importDefault(require("elliptic"));
var js_sha3_1 = require("js-sha3");
var ec = new elliptic_1["default"].ec('secp256k1');
function generateKeyPair() {
    return ec.genKeyPair();
}
exports.generateKeyPair = generateKeyPair;
function generateWallet() {
    var keyPair = generateKeyPair();
    var privateKey = keyPair.getPrivate('hex').toString();
    var publicKey = keyPair.getPublic(true, 'hex').toString();
    var address = publicKeyToChecksumAddress(publicKey);
    return { privateKey: privateKey, publicKey: publicKey, address: address };
}
exports.generateWallet = generateWallet;
function generateChecksumAddress(address) {
    var addr = address.slice(3);
    var addrHash = (0, js_sha3_1.keccak256)(addr.toLowerCase());
    var chkAddr = '';
    for (var i = 0; i < addr.length; i++) {
        if (parseInt(addrHash[i], 16) >= 8)
            chkAddr += addr[i].toUpperCase();
        else
            chkAddr += addr[i];
    }
    return "xe_" + chkAddr;
}
exports.generateChecksumAddress = generateChecksumAddress;
function checksumAddressIsValid(address) {
    if (!/^(xe_[a-fA-F0-9]{40})$/.test(address))
        return false;
    if (address !== generateChecksumAddress(address))
        return false;
    return true;
}
exports.checksumAddressIsValid = checksumAddressIsValid;
function publicKeyToChecksumAddress(publicKey) {
    var hash = (0, js_sha3_1.keccak256)(publicKey);
    var addr = 'xe_' + hash.substring(hash.length - 40, hash.length);
    return generateChecksumAddress(addr);
}
exports.publicKeyToChecksumAddress = publicKeyToChecksumAddress;
function privateKeyToPublicKey(privateKey) {
    return ec.keyFromPrivate(privateKey, 'hex').getPublic(true, 'hex');
}
exports.privateKeyToPublicKey = privateKeyToPublicKey;
function privateKeyToChecksumAddress(privateKey) {
    var publicKey = privateKeyToPublicKey(privateKey);
    return publicKeyToChecksumAddress(publicKey);
}
exports.privateKeyToChecksumAddress = privateKeyToChecksumAddress;
function xeStringFromMicroXe(mxe, format) {
    var s = mxe.toString();
    var fraction = s.substr(-6, 6).padStart(6, '0');
    var whole = s.substr(0, s.length - 6) || '0';
    if (format)
        whole = parseInt(whole).toLocaleString('en-US');
    return whole + "." + fraction;
}
exports.xeStringFromMicroXe = xeStringFromMicroXe;
function toMicroXe(xe) {
    var s = typeof xe === 'number' ? xe.toString() : xe;
    var parts = s.split('.');
    var whole = parts[0];
    var fraction = parts.length > 1 ? parts[1].padEnd(6, '0') : '000000';
    return parseInt("" + whole + fraction);
}
exports.toMicroXe = toMicroXe;
function formatXe(xe, format) {
    var mxe = toMicroXe(xe);
    return xeStringFromMicroXe(mxe, format);
}
exports.formatXe = formatXe;
function generateSignature(privateKey, msg) {
    var msgHash = (0, sha256_1["default"])(msg).toString();
    var msgHashByteArray = elliptic_1["default"].utils.toArray(msgHash, 'hex');
    var signatureObj = ec.sign(msgHashByteArray, ec.keyFromPrivate(privateKey), 'hex', { canonical: true });
    var r = signatureObj.r.toString('hex', 32);
    var s = signatureObj.s.toString('hex', 32);
    var i = (typeof signatureObj.recoveryParam === 'number')
        ? signatureObj.recoveryParam.toString(16).padStart(2, '0')
        : '';
    return r + s + i;
}
exports.generateSignature = generateSignature;
function verifySignatureAddress(msg, signature, address) {
    var publicKey = recoverPublicKeyFromSignedMessage(msg, signature);
    var derivedAddress = publicKeyToChecksumAddress(publicKey);
    return address === derivedAddress;
}
exports.verifySignatureAddress = verifySignatureAddress;
function recoverPublicKeyFromSignedMessage(msg, signature) {
    var signatureObj = { r: signature.slice(0, 64), s: signature.slice(64, 128) };
    var recoveryParam = parseInt(signature.slice(128, 130), 16);
    var msgHash = (0, sha256_1["default"])(msg).toString();
    var msgHashByteArray = elliptic_1["default"].utils.toArray(msgHash, 'hex');
    var publicKey = ec.recoverPubKey(msgHashByteArray, signatureObj, recoveryParam, 'hex');
    return publicKey.encode('hex', true);
}
exports.recoverPublicKeyFromSignedMessage = recoverPublicKeyFromSignedMessage;
function recoverAddressFromSignedMessage(msg, signature) {
    var publicKey = recoverPublicKeyFromSignedMessage(msg, signature);
    var derivedAddress = publicKeyToChecksumAddress(publicKey);
    return derivedAddress;
}
exports.recoverAddressFromSignedMessage = recoverAddressFromSignedMessage;
exports["default"] = {
    generateKeyPair: generateKeyPair,
    generateWallet: generateWallet,
    generateChecksumAddress: generateChecksumAddress,
    checksumAddressIsValid: checksumAddressIsValid,
    publicKeyToChecksumAddress: publicKeyToChecksumAddress,
    privateKeyToChecksumAddress: privateKeyToChecksumAddress,
    privateKeyToPublicKey: privateKeyToPublicKey,
    generateSignature: generateSignature,
    verifySignatureAddress: verifySignatureAddress,
    recoverPublicKeyFromSignedMessage: recoverPublicKeyFromSignedMessage,
    recoverAddressFromSignedMessage: recoverAddressFromSignedMessage,
    xeStringFromMicroXe: xeStringFromMicroXe,
    toMicroXe: toMicroXe,
    formatXe: formatXe
};
