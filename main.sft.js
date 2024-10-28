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

  // Cria o token com dados privados e públicos
  createToken(data, encryptionKey, hmacKey, ttl = 300) {
    // Armazena dados privados passados em `data.private`
    const privateData = data.private || null;
    
    // Dados públicos
    const publicData = { 
      exp: Date.now() + ttl * 1000,  // Expiração única baseada no TTL
      scope: data.scope || null, 
      public: data.public || null,
      locality: data.locality || null,
      ip: data.ip || null,
      userAgent: data.userAgent || null
    };

    // Criptografa dados privados com AES-CTR
    const privatePayload = Buffer.from(JSON.stringify({ private: privateData }));
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(encryptionKey, 'hex'), iv);
    const encryptedPrivatePayload = Buffer.concat([iv, cipher.update(privatePayload), cipher.final()]);

    // Codifica o publicData
    const publicPayload = SFT.toBase64Url(Buffer.from(JSON.stringify(publicData)));

    // Cria o nonce com ID de sessão e timestamp
    const sessionId = crypto.randomBytes(8).toString('hex');
    const nonce = `${sessionId}${Date.now().toString(36)}`;

    // Assinatura HMAC SHA-256
    const unsignedToken = Buffer.concat([encryptedPrivatePayload, Buffer.from(publicPayload), Buffer.from(nonce)]);
    const signature = crypto.createHmac('sha256', Buffer.from(hmacKey, 'hex')).update(unsignedToken).digest();

    // Constrói o token final
    return `${SFT.toBase64Url(encryptedPrivatePayload)}.${publicPayload}.${SFT.toBase64Url(Buffer.from(nonce))}.${SFT.toBase64Url(signature)}`;
  }

  // Verifica e decodifica o token, com validação opcional de IP, User-Agent e Localidade
  verifyToken(token, encryptionKey, hmacKey, expectedIp = null, expectedUserAgent = null, expectedLocality = null) {
    const [encryptedPrivatePayloadB64, publicPayloadB64, nonceB64, signatureB64] = token.split('.');

    try {
      // Decodifica as partes do token
      const encryptedPrivatePayload = SFT.fromBase64Url(encryptedPrivatePayloadB64);
      const publicPayload = JSON.parse(SFT.fromBase64Url(publicPayloadB64).toString());
      const nonce = SFT.fromBase64Url(nonceB64).toString();
      const signature = SFT.fromBase64Url(signatureB64);

      // Verifica a expiração
      const currentTimestamp = Date.now();
      if (currentTimestamp > publicPayload.exp) throw new Error('Token expirado.');

      // Verifica a assinatura HMAC SHA-256
      const unsignedToken = Buffer.concat([encryptedPrivatePayload, Buffer.from(publicPayloadB64), Buffer.from(nonce)]);
      const expectedSignature = crypto.createHmac('sha256', Buffer.from(hmacKey, 'hex')).update(unsignedToken).digest();
      if (!crypto.timingSafeEqual(signature, expectedSignature)) throw new Error('Assinatura inválida.');

      // Descriptografa dados privados
      const iv = encryptedPrivatePayload.slice(0, 16);
      const encryptedData = encryptedPrivatePayload.slice(16);
      const decipher = crypto.createDecipheriv('aes-256-ctr', Buffer.from(encryptionKey, 'hex'), iv);
      const decryptedPrivatePayload = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
      const privatePayload = JSON.parse(decryptedPrivatePayload.toString()).private || {};

      // Validações opcionais de IP, User-Agent e Localidade
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

// Exemplo de uso da classe SFT
const encryptionKey = crypto.randomBytes(32).toString('hex');
const hmacKey = crypto.randomBytes(32).toString('hex');
const sft = new SFT();

const data = { 
  locality: 'BR',
  ip: '192.168.0.1', 
  userAgent: 'Mozilla/5.0',
  scope: ['read', 'write'], 
  public: { name: 'germano' },
  private: { userId: 42, role: 'admin', },
};

const token = sft.createToken(data, encryptionKey, hmacKey, 60);
console.log('Token:', token);
console.log('Token:', `'${token}', ${encryptionKey}', '${hmacKey}'`);

try {
  const decodedData = sft.verifyToken(token, encryptionKey, hmacKey, '192.168.0.1', 'Mozilla/5.0', 'BR');
  console.log('Dados Decodificados:', decodedData);
} catch (error) {
  console.error(error.message);
}
