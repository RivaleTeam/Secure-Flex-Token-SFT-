# Secure Flex Token (SFT)

## Descrição do Projeto
O **Secure Flex Token (SFT)** é uma solução de autenticação customizada desenvolvida para oferecer segurança avançada e flexibilidade. Inspirado em **JSON Web Tokens (JWT)**, o SFT utiliza criptografia AES e HMAC SHA-256 para criar tokens seguros e personalizáveis.

### Funcionalidades
- **Criptografia de Dados Privados**: O SFT criptografa dados privados usando AES-CTR para garantir a confidencialidade.
- **Assinatura com HMAC SHA-256**: Cada token é assinado para assegurar a integridade dos dados.
- **Claims Opcionais**: Permite validação opcional de IP, User-Agent e Localidade.
- **Expiração Personalizável**: Configurável com um TTL (Time-To-Live) para garantir validade temporária.

### Tecnologias Utilizadas
- **Node.js**: Utilizado para a execução do código principal.
- **Criptografia AES-CTR**: Para criptografia de dados privados.
- **HMAC SHA-256**: Para assinatura dos tokens.
- **Base64 URL-safe**: Para encoding e decoding de dados.

## Como Usar

### 1. Instalar Dependências
Primeiro, instale o Node.js, que é necessário para rodar o projeto.

### 2. Exemplo de Criação e Verificação de Token
Veja um exemplo básico de uso para criar e verificar tokens com claims customizados.

```javascript
const crypto = require('crypto');
const sft = new SFT();

// Definindo as chaves de criptografia e HMAC
const encryptionKey = crypto.randomBytes(32).toString('hex');
const hmacKey = crypto.randomBytes(32).toString('hex');

// Dados de exemplo
const data = { 
  locality: 'BR',
  ip: '192.168.0.1', 
  userAgent: 'Mozilla/5.0',
  scope: ['read', 'write'], 
  public: { name: 'Lucas' },
  private: { userId: 42, role: 'admin' },
};

// Criação do Token
const token = sft.createToken(data, encryptionKey, hmacKey, 60);
console.log('Token Gerado:', token);

// Verificação do Token
try {
  const decodedData = sft.verifyToken(token, encryptionKey, hmacKey, '192.168.0.1', 'Mozilla/5.0', 'BR');
  console.log('Dados Decodificados:', decodedData);
} catch (error) {
  console.error('Erro ao verificar token:', error.message);
}
