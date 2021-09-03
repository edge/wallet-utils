/// <reference types="node" />
import elliptic from 'elliptic';
declare type Address = string;
declare type ChecksumAddress = Address;
declare type Message = string;
declare type PrivateKey = Uint8Array | Buffer | string | number[] | elliptic.ec.KeyPair;
declare type PublicKey = string;
declare type SigningPrivateKey = Buffer | elliptic.ec.KeyPair;
declare type Signature = string;
declare type Wallet = {
    address: Address;
    privateKey: PrivateKey;
    publicKey: PublicKey;
};
export declare function generateKeyPair(): elliptic.ec.KeyPair;
export declare function generateWallet(): Wallet;
export declare function generateChecksumAddress(address: Address): ChecksumAddress;
export declare function checksumAddressIsValid(address: Address): boolean;
export declare function publicKeyToChecksumAddress(publicKey: PublicKey): ChecksumAddress;
export declare function privateKeyToPublicKey(privateKey: PrivateKey): PublicKey;
export declare function privateKeyToChecksumAddress(privateKey: PrivateKey): ChecksumAddress;
export declare function xeStringFromMicroXe(mxe: number, format: boolean): string;
export declare function toMicroXe(xe: string | number): number;
export declare function formatXe(xe: string | number, format: boolean): string;
export declare function generateSignature(privateKey: SigningPrivateKey, msg: Message): Signature;
export declare function verifySignatureAddress(msg: string, signature: Signature, address: Address): boolean;
export declare function recoverPublicKeyFromSignedMessage(msg: Message, signature: Signature): PublicKey;
export declare function recoverAddressFromSignedMessage(msg: Message, signature: Signature): Address;
export {};
