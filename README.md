# Secure Flex Token (SFT)

## Descrição do Projeto

O **Secure Flex Token (SFT)** é uma solução de autenticação customizada desenvolvida para oferecer segurança avançada e flexibilidade. Inspirado em **JSON Web Tokens (JWT)**, o SFT utiliza criptografia **AES-256-GCM** e **HMAC SHA-256** para criar tokens seguros e personalizáveis.

### Funcionalidades
- **Criptografia de Dados Privados**: O SFT criptografa dados privados usando **AES-256-GCM** para garantir a confidencialidade e integridade.
- **Assinatura com HMAC SHA-256**: Cada token é assinado para assegurar a integridade dos dados.
- **Claims Opcionais**: Permite validação opcional de **IP**, **User-Agent** e **Localidade**.
- **Expiração Personalizável**: Configurável com um TTL (Time-To-Live) para garantir validade temporária.
- **Nonce e Session ID**: Garante que cada token seja único, com um identificador de sessão e timestamp.

### Tecnologias Utilizadas
- **Node.js**: Utilizado para a execução do código principal.
- **Criptografia AES-256-GCM**: Para criptografia de dados privados.
- **HMAC SHA-256**: Para assinatura dos tokens.
- **Base64 URL-safe**: Para encoding e decoding de dados.

## Como Usar

### 1. Instalar Dependências
Primeiro, instale o **Node.js**, que é necessário para rodar o projeto.

### 2. Exemplo de Criação e Verificação de Token
Veja um exemplo básico de uso para criar e verificar tokens com claims customizados.

```javascript
const crypto = require('crypto');
const SFT = require('./SFT'); // Supondo que o código da classe esteja no arquivo 'SFT.js'

// Definindo as chaves de criptografia e HMAC
const password1 = 'password1';
const password2 = 'password2';

// Dados de exemplo
const data = { 
  locality: 'BR',
  ip: '192.168.0.1', 
  userAgent: 'Mozilla/5.0',
  scope: ['read', 'write'], 
  public: { name: 'Germano' },
  private: { userId: 42, role: 'admin' },
};

// Criação do Token
const token = SFT.createToken(data, password1, password2, 60);
console.log('Token Gerado:', token);

// Verificação do Token
try {
  const decodedData = SFT.verifyToken(token, password1, password2, '192.168.0.1', 'Mozilla/5.0', 'BR');
  console.log('Dados Decodificados:', decodedData);
} catch (error) {
  console.error('Erro ao verificar token:', error.message);
}
