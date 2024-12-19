/**
 * Projeto: Secure Flex Token (SFT)
 * 
 * Explicação do Nome:
 * O Secure Flex Token (SFT) é uma solução de autenticação customizada que oferece segurança avançada e flexibilidade.
 * Inspirado no conceito de JSON Web Tokens (JWT), o SFT usa criptografia AES e HMAC SHA-256 para assinar e verificar tokens.
 * Ele suporta claims opcionais para validação de IP, User-Agent e localidade.
 * 
 * Esse sistema permite a criação de tokens seguros e personalizados que podem ser configurados para diferentes níveis de segurança,
 * suportando requisitos variados de autenticidade e integridade de dados.
 * 
 * Uso:
 * 1. Instancie a classe `SFT`.
 * 2. Use `createToken(data, encryptionKey, hmacKey, ttl)` para criar um token com os dados e claims desejados.
 * 3. Verifique o token com `verifyToken(token, encryptionKey, hmacKey, expectedIp, expectedUserAgent, expectedLocality)` 
 *    para garantir que ele seja válido e autêntico.
 */

const crypto = require('crypto');

class SFT {
  // Codifica em Base64 URL-safe
  static toBase64Url(buffer) {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Decodifica de Base64 URL-safe
  static fromBase64Url(base64) {
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    return Buffer.from(base64, 'base64');
  }

  // Deriva encryptionKey e hmacKey usando password1 e password2
  static deriveKeys(password1, password2) {
    const salt1 = crypto.createHash('sha256').update(password2).digest();
    const encryptionKey = crypto.pbkdf2Sync(password1, salt1, 100000, 32, 'sha512'); // 32 bytes para AES-256

    const salt2 = crypto.createHash('sha256').update(password1).digest();
    const hmacKey = crypto.pbkdf2Sync(password2, salt2, 100000, 32, 'sha512'); // 32 bytes para HMAC-SHA-256

    return { encryptionKey, hmacKey };
  }

  // Cria o token com dados privados e públicos usando AES-GCM
  static createToken(data, password1, password2, ttl = null) {
    if (!data || typeof data !== 'object') throw new Error('Dados inválidos para criação de token.');

    // Deriva encryptionKey e hmacKey usando password1 e password2
    const { encryptionKey, hmacKey } = SFT.deriveKeys(password1, password2);

    // Dados públicos, incluindo apenas campos opcionais se eles existirem
    const publicData = { 
      scope: data.scope || null,
      public: data.public || null,
    };

    // Define expiração apenas se `ttl` for passado
    if (ttl !== null) {
      publicData.exp = Date.now() + ttl * 1000; // Expiração baseada no TTL
    }

    // Inclui `locality`, `ip` e `userAgent` apenas se fornecidos
    if (data.locality) publicData.locality = data.locality;
    if (data.ip) publicData.ip = data.ip;
    if (data.userAgent) publicData.userAgent = data.userAgent;

    // Dados privados
    const privatePayload = Buffer.from(JSON.stringify({ private: data.private || null }));

    // Criptografa dados privados com AES-GCM
    const iv = crypto.randomBytes(12); // GCM usa IV de 12 bytes
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encryptedPrivatePayload = Buffer.concat([cipher.update(privatePayload), cipher.final()]);
    const authTag = cipher.getAuthTag(); // Obtém a tag de autenticação

    // Codifica o publicData
    const publicPayload = SFT.toBase64Url(Buffer.from(JSON.stringify(publicData)));

    // Cria o nonce com ID de sessão e timestamp
    const sessionId = crypto.randomBytes(8).toString('hex');
    const nonce = `${sessionId}${Date.now().toString(36)}`;

    // Assinatura HMAC SHA-256
    const unsignedToken = Buffer.concat([iv, encryptedPrivatePayload, authTag, Buffer.from(publicPayload), Buffer.from(nonce)]);
    const signature = crypto.createHmac('sha256', hmacKey).update(unsignedToken).digest();

    // Constrói o token final
    return `${SFT.toBase64Url(iv)}.${SFT.toBase64Url(encryptedPrivatePayload)}.${SFT.toBase64Url(authTag)}.${publicPayload}.${SFT.toBase64Url(Buffer.from(nonce))}.${SFT.toBase64Url(signature)}`;
  }

  // Verifica e decodifica o token usando AES-GCM
  static verifyToken(token, password1, password2, expectedIp = null, expectedUserAgent = null, expectedLocality = null) {
    if (typeof token !== 'string' || !token.includes('.')) throw new Error('Token inválido.');

    // Deriva encryptionKey e hmacKey usando password1 e password2
    const { encryptionKey, hmacKey } = SFT.deriveKeys(password1, password2);

    const [ivB64, encryptedPrivatePayloadB64, authTagB64, publicPayloadB64, nonceB64, signatureB64] = token.split('.');

    try {
      // Decodifica as partes do token
      const iv = SFT.fromBase64Url(ivB64);
      const encryptedPrivatePayload = SFT.fromBase64Url(encryptedPrivatePayloadB64);
      const authTag = SFT.fromBase64Url(authTagB64);
      const publicPayload = JSON.parse(SFT.fromBase64Url(publicPayloadB64).toString());
      const nonce = SFT.fromBase64Url(nonceB64).toString();
      const signature = SFT.fromBase64Url(signatureB64);

      // Verifica a expiração, se presente
      if (publicPayload.exp) {
        const currentTimestamp = Date.now();
        if (currentTimestamp > publicPayload.exp) throw new Error('Token expirado.');
      }

      // Verifica a assinatura HMAC SHA-256
      const unsignedToken = Buffer.concat([iv, encryptedPrivatePayload, authTag, Buffer.from(publicPayloadB64), Buffer.from(nonce)]);
      const expectedSignature = crypto.createHmac('sha256', hmacKey).update(unsignedToken).digest();
      if (!crypto.timingSafeEqual(signature, expectedSignature)) throw new Error('Assinatura inválida.');

      // Descriptografa e verifica dados privados com AES-GCM
      const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
      decipher.setAuthTag(authTag); // Define a tag para verificação
      const decryptedPrivatePayload = Buffer.concat([decipher.update(encryptedPrivatePayload), decipher.final()]);
      const privatePayload = JSON.parse(decryptedPrivatePayload.toString()).private || {};

      // Validações opcionais de IP, User-Agent e Localidade, apenas se presentes
      if (expectedIp && publicPayload.ip && publicPayload.ip !== expectedIp) {
        throw new Error('IP não corresponde.');
      }
      if (expectedUserAgent && publicPayload.userAgent && publicPayload.userAgent !== expectedUserAgent) {
        throw new Error('User Agent não corresponde.');
      }
      if (expectedLocality && publicPayload.locality && publicPayload.locality !== expectedLocality) {
        throw new Error('Localidade não corresponde.');
      }

      // Retorna os dados separados em private e public
      return { private: privatePayload, public: publicPayload };
    } catch (error) {
      throw new Error(`Erro na verificação do token: ${error.message}`);
    }
  }
}

module.exports = SFT;
