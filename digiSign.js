const fs = require('fs');
const crypto = require('crypto');

// Function to check if RSA key pair exists
function rsaKeyPairExists() {
    return fs.existsSync('private.pem') && fs.existsSync('public.pem');
}

// Function to generate RSA key pair
function generateKeyPair() {
    if (rsaKeyPairExists()) {
        console.log('RSA key pair already exists.');
        return;
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // key size
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    fs.writeFileSync('private.pem', privateKey);
    fs.writeFileSync('public.pem', publicKey);

    console.log('RSA key pair generated and saved successfully.');
}

// Function to sign a file
function signFile(filePath) {
    if (!rsaKeyPairExists()) {
        console.log('RSA key pair does not exist. Generate keys first.');
        return;
    }

    const privateKey = fs.readFileSync('private.pem', 'utf8');
    const fileData = fs.readFileSync(filePath);
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(fileData);
    const signature = sign.sign(privateKey, 'base64');
    return signature;
}

// Function to verify signature
function verifySignature(filePath, signaturePath) {
    if (!rsaKeyPairExists()) {
        console.log('RSA key pair does not exist. Generate keys first.');
        return false;
    }

    const publicKey = fs.readFileSync('public.pem', 'utf8');
    const fileData = fs.readFileSync(filePath);
    const signature = fs.readFileSync(signaturePath, 'utf8');

    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(fileData);

    const isValid = verify.verify(publicKey, signature, 'base64');
    return isValid;
}

// Example usage
function exampleUsage() {
    const filePath = 'example.txt'; // Replace with your file path

    // Generate key pair if not already existing
    generateKeyPair();

    // Sign file if key pair exists
    if (rsaKeyPairExists()) {
        const signature = signFile(filePath);
        if (signature) {
            console.log('Digital Signature:', signature);

            // Save signature to file (optional)
            fs.writeFileSync('signature.txt', signature, 'utf8');

            // Verify signature
            const isVerified = verifySignature(filePath, 'signature.txt');
            if (isVerified) {
                console.log('Signature is valid. File has not been tampered with.');
            } else {
                console.log('Invalid signature. File may have been tampered with.');
            }
        }
    }
}

// Run example usage
exampleUsage();
