require('dotenv').config();
const crypto = require('crypto');

const AES_SECRET_KEY = process.env.AES_SECRET_KEY;

// Encrypt private key
function encryptPrivateKey(privateKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(AES_SECRET_KEY), iv);
    let encrypted = cipher.update(privateKey);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Decrypt private key
function decryptPrivateKey(encryptedPrivateKey) {
    const parts = encryptedPrivateKey.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(AES_SECRET_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

module.exports = { encryptPrivateKey, decryptPrivateKey };
