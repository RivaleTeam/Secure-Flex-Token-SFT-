const crypto = require('crypto');
const util = require('util');

class SFT {
    /**
     * Secure Function Token (SFT) class for creating and verifying secure tokens.
     * This class provides methods for token generation and verification using strong
     * cryptographic operations including AES-256-GCM encryption and HMAC-SHA256.
     */
    
    static toBase64Url(buffer) {
        /**
         * Convert a buffer to URL-safe base64 without padding.
         * @param {Buffer|string} buffer - Input data to be encoded
         * @return {string} URL-safe base64 encoded string without padding
         */
        if (typeof buffer === 'string') {
            buffer = Buffer.from(buffer, 'utf8');
        }
        return buffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    static fromBase64Url(base64Str) {
        /**
         * Convert a URL-safe base64 string back to original bytes.
         * @param {string} base64Str - URL-safe base64 string (with or without padding)
         * @return {Buffer} Decoded binary data
         */
        let padding = base64Str.length % 4;
        if (padding) {
            base64Str += '='.repeat(4 - padding);
        }
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        return Buffer.from(base64Str, 'base64');
    }

    static async _deriveKey(password, saltBase, securityLevel, contextSalt = null) {
        /**
         * Derive a cryptographic key using PBKDF2.
         * @param {Buffer|string} password - The input password/passphrase
         * @param {Buffer|string} saltBase - Base value used to generate the salt
         * @param {string} securityLevel - Security level ("low", "medium", or "high")
         * @param {Buffer|null} contextSalt - Optional additional salt
         * @return {Buffer} Derived key
         */
        if (typeof password === 'string') {
            password = Buffer.from(password, 'utf8');
        }
        if (typeof saltBase === 'string') {
            saltBase = Buffer.from(saltBase, 'utf8');
        }

        // Generate base salt
        const salt = crypto.createHash('sha256').update(saltBase).digest();
        const finalSalt = contextSalt ? Buffer.concat([salt, contextSalt]) : salt;

        const securityParams = {
            "low": { hash: 'sha256', iterations: 10000 },
            "medium": { hash: 'sha256', iterations: 100000 },
            "high": { hash: 'sha512', iterations: 1000000 }
        };

        const params = securityParams[securityLevel.toLowerCase()];
        if (!params) {
            throw new Error("Invalid security level - must be 'low', 'medium' or 'high'");
        }

        return new Promise((resolve, reject) => {
            crypto.pbkdf2(password, finalSalt, params.iterations, 32, params.hash, (err, derivedKey) => {
                if (err) reject(err);
                else resolve(derivedKey);
            });
        });
    }

    static async deriveKeys(password1, password2, securityLevel, contextSalt = null) {
        /**
         * Derive encryption and HMAC keys from two passwords.
         * @param {string} password1 - First password for key derivation
         * @param {string} password2 - Second password for key derivation
         * @param {string} securityLevel - Security level ("low", "medium", or "high")
         * @param {Buffer|null} contextSalt - Optional additional salt
         * @return {Object} Dictionary containing 'encryptionKey' and 'hmacKey'
         */
        if (typeof contextSalt === 'string') {
            contextSalt = Buffer.from(contextSalt, 'utf8');
        }

        const [encryptionKey, hmacKey] = await Promise.all([
            this._deriveKey(password1, password2, securityLevel, contextSalt),
            this._deriveKey(password2, password1, securityLevel, contextSalt)
        ]);

        return { encryptionKey, hmacKey };
    }

    static async createToken(data, password1, password2, contextSalt = Buffer.from('context_salt'), securityLevel = 'medium', ttl = 30) {
        /**
         * Create a secure token with encrypted payload and HMAC signature.
         * @param {Object} data - Dictionary containing token data
         * @param {string} password1 - First password for key derivation
         * @param {string} password2 - Second password for key derivation
         * @param {Buffer} contextSalt - Additional salt for key derivation
         * @param {string} securityLevel - Security level ("low", "medium", or "high")
         * @param {number} ttl - Time-to-live in seconds
         * @return {string} The generated secure token
         */

        if (!data || typeof data !== 'object') {
            throw new Error('Invalid data for token creation');
        }

        // Derive 256-bit keys
        const { encryptionKey, hmacKey } = await this.deriveKeys(password1, password2, securityLevel, contextSalt);
        
        const publicData = {
            scope: data.scope,
            public: data.public
        };

        // Set expiration if TTL is provided
        if (ttl !== null) {
            publicData.exp = Date.now() + ttl * 1000;
        }

        // Prepare private data
        const privatePayload = Buffer.from(JSON.stringify({ private: data.private }), 'utf8');

        // Encrypt private data with AES-256-GCM (256-bit key)
        const iv = crypto.randomBytes(12); // 12 bytes IV for GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
        const encryptedParts = [
            cipher.update(privatePayload),
            cipher.final()
        ];
        const encryptedPrivatePayload = Buffer.concat(encryptedParts);
        const authTag = cipher.getAuthTag(); // 128-bit authentication tag

        // Encode public data
        const publicPayload = this.toBase64Url(Buffer.from(JSON.stringify(publicData), 'utf8'));

        // Create nonce with session ID and timestamp
        const sessionId = crypto.randomBytes(8).toString('hex');
        const nonce = `${sessionId}${Date.now().toString(16)}`;

        // Create HMAC-SHA256 signature (using 256-bit key)
        const unsignedToken = Buffer.concat([
            iv,
            encryptedPrivatePayload,
            authTag,
            Buffer.from(publicPayload, 'utf8'),
            Buffer.from(nonce, 'utf8')
        ]);
        const signature = crypto.createHmac('sha256', hmacKey).update(unsignedToken).digest();

        // Build final token
        const tokenParts = [
            this.toBase64Url(iv),
            this.toBase64Url(encryptedPrivatePayload),
            this.toBase64Url(authTag),
            publicPayload,
            this.toBase64Url(Buffer.from(nonce, 'utf8')),
            this.toBase64Url(signature)
        ];

        return tokenParts.join('.').toString();
    }

    static async verifyToken(token, password1, password2, contextSalt = null, securityLevel = 'medium') {
        /**
         * Verify and decrypt a secure token.
         * @param {string} token - The token to verify
         * @param {string} password1 - First password used in token creation
         * @param {string} password2 - Second password used in token creation
         * @param {string} securityLevel - Security level ("low", "medium", or "high")
         * @param {Buffer|null} contextSalt - Optional additional salt used in token creation
         * @return {Object} Dictionary containing decrypted 'private' and 'public' data
         */
        if (typeof token !== 'string' || token.split('.').length !== 6) {
            throw new Error('Invalid token format');
        }

        // Derive 256-bit keys
        const { encryptionKey, hmacKey } = await this.deriveKeys(password1, password2, securityLevel, contextSalt);

        const parts = token.split('.');
        try {
            const iv = this.fromBase64Url(parts[0]);
            const encryptedPrivatePayload = this.fromBase64Url(parts[1]);
            const authTag = this.fromBase64Url(parts[2]);
            const publicPayload = this.fromBase64Url(parts[3]);
            const nonce = this.fromBase64Url(parts[4]);
            const signature = this.fromBase64Url(parts[5]);

            // Verify HMAC-SHA256 signature (256-bit key)
            const unsignedToken = Buffer.concat([
                iv,
                encryptedPrivatePayload,
                authTag,
                Buffer.from(parts[3], 'utf8'),
                nonce
            ]);
            const expectedSignature = crypto.createHmac('sha256', hmacKey).update(unsignedToken).digest();
            
            if (!crypto.timingSafeEqual(signature, expectedSignature)) {
                throw new Error('Invalid signature');
            }

            // Decode public payload
            const publicData = JSON.parse(publicPayload.toString('utf8'));

            // Check expiration if present
            if (publicData.exp && Date.now() > publicData.exp) {
                throw new Error('Token expired');
            }

            // Decrypt private payload using AES-256-GCM
            const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
            decipher.setAuthTag(authTag);
            const decryptedParts = [
                decipher.update(encryptedPrivatePayload),
                decipher.final()
            ];
            const decryptedPrivatePayload = Buffer.concat(decryptedParts);
            const privateData = JSON.parse(decryptedPrivatePayload.toString('utf8')).private || {};

            return { private: privateData, public: publicData.public };
        } catch (err) {
            throw new Error(`Token verification error: ${err.message}`);
        }
    }
}

async function benchmarkCryptoOperations(iterations = 100) {
    /** Benchmark token creation and verification operations. */
    // Test data setup
    const data = {
        private: { user_id: 123, role: 'admin' },
        public: { name: 'John Doe' },
        scope: 'read:write'
    };
    const password1 = "d0803cae57d5b17e1327521f5c702be5fab613e9";
    const password2 = "94be45ad424802a2ccdf3e4ed4d917409527d601";
    const contextSalt = Buffer.from("ContextSaltTest");
    const securityLevel = "high";
    
    // Benchmark token creation
    const createTimes = [];
    let token;
    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        token = await SFT.createToken(data, password1, password2, contextSalt, securityLevel, 3600);
        console.log(token);
        const end = process.hrtime.bigint();
        createTimes.push(Number(end - start) / 1e6); // Convert to milliseconds
    }
    
    // Benchmark token verification
    const verifyTimes = [];
    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        try {
            const verified = await SFT.verifyToken(
                token,
                password1,
                password2,
                securityLevel,
                contextSalt
            );
        } catch (err) {
            console.error('Verification error:', err);
        }
        const end = process.hrtime.bigint();
        verifyTimes.push(Number(end - start) / 1e6); // Convert to milliseconds
    }
    
    // Calculate statistics
    const calcStats = (times) => {
        const sum = times.reduce((a, b) => a + b, 0);
        const avg = sum / times.length;
        const min = Math.min(...times);
        const max = Math.max(...times);
        return { avg, min, max };
    };
    
    const createStats = calcStats(createTimes);
    const verifyStats = calcStats(verifyTimes);
    
    // Print results
    console.log(`\nBenchmark Results (${iterations} iterations):`);
    console.log("Token Creation:");
    console.log(`  Average: ${createStats.avg.toFixed(3)} ms`);
    console.log(`  Min: ${createStats.min.toFixed(3)} ms`);
    console.log(`  Max: ${createStats.max.toFixed(3)} ms`);
    
    console.log("\nToken Verification:");
    console.log(`  Average: ${verifyStats.avg.toFixed(3)} ms`);
    console.log(`  Min: ${verifyStats.min.toFixed(3)} ms`);
    console.log(`  Max: ${verifyStats.max.toFixed(3)} ms`);
}

// Run benchmark if executed directly
if (require.main === module) {
    (async () => {
        await benchmarkCryptoOperations(100);
    })();
}

module.exports = SFT;
