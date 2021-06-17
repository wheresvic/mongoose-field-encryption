export function fieldEncryption(schema: any, options: any): void;
export function encrypt(clearText: any, secret: any, saltGenerator: any): string;
/**
 * Decryption has a default fallback for the deprecated algorithm
 *
 * @param {*} encryptedHex
 * @param {*} secret
 */
export function decrypt(encryptedHex: any, secret: any): string;
export function encryptAes256Ctr(text: any, secret: any): string;
