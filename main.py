const express = require('express');
const libsignal = require('libsignal');
const crypto = require('crypto');

const app = express();
app.use(express.json());

let users = {}; 

function toBase64(buffer) {
    return Buffer.from(buffer).toString('base64');
}

async function generateKeys() {
    const identityKeyPair = await libsignal.KeyHelper.generateIdentityKeyPair();
    const registrationId = crypto.randomInt(1, 16380);
    const preKey = await libsignal.KeyHelper.generatePreKey(crypto.randomInt(1, 16380));
    const signedPreKey = await libsignal.KeyHelper.generateSignedPreKey(identityKeyPair, crypto.randomInt(1, 16380));

    return {
        identityKey: identityKeyPair,
        registrationId,
        preKey,
        signedPreKey
    };
}

app.post('/register', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).send({ error: 'Username required' });

    const keys = await generateKeys();
    users[username] = keys;

    res.send({
        username,
        publicKey: toBase64(keys.identityKey.publicKey),
        preKey: toBase64(keys.preKey.keyPair.publicKey),
        signedPreKey: toBase64(keys.signedPreKey.keyPair.publicKey),
    });
});

app.post('/send', async (req, res) => {
    const { sender, receiver, message } = req.body;
    if (!users[receiver]) return res.status(404).send({ error: 'Receiver not found' });

    const receiverKeys = users[receiver];

    const sessionBuilder = new libsignal.SessionBuilder(receiverKeys.identityKey.publicKey);
    const sessionCipher = new libsignal.SessionCipher(receiverKeys.identityKey.publicKey);
    const encryptedMessage = await sessionCipher.encrypt(new TextEncoder().encode(message));

    res.send({
        sender,
        receiver,
        encryptedMessage: toBase64(encryptedMessage.ciphertext)
    });
});

app.post('/decrypt', async (req, res) => {
    const { receiver, encryptedMessage } = req.body;
    if (!users[receiver]) return res.status(404).send({ error: 'Receiver not found' });

    const receiverKeys = users[receiver];

    const sessionCipher = new libsignal.SessionCipher(receiverKeys.identityKey.publicKey);
    const decryptedBytes = await sessionCipher.decrypt(new Uint8Array(Buffer.from(encryptedMessage, 'base64')));
    const decryptedMessage = new TextDecoder().decode(decryptedBytes);

    res.send({ receiver, decryptedMessage });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
