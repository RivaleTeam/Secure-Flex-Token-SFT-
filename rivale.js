import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync, copyFileSync } from "fs";
import { resolve } from "path";
import { homedir } from "os";
import { createInterface } from "readline";
import inquirer from "inquirer";
import axios from "axios";
import bip39 from "bip39";
import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from "bitcoinjs-lib";
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "crypto";

const bip32 = BIP32Factory(ecc);
const SFT = require("./sft.js");

class BitcoinWalletCLI {
  constructor() {
    this.walletDir = resolve(homedir(), ".rivale-wallet");
    this.walletFile = resolve(this.walletDir, "wallet.riv");
    this.walletFileEnc = resolve(this.walletDir, "wallet.riv.enc");
    this.currentWallet = null;
    this.networks = {
      mainnet: bitcoin.networks.bitcoin,
      testnet: bitcoin.networks.testnet,
    };

    this.ensureWalletDir();
    console.log(this.walletDir)
  }

  ensureWalletDir() {
    if (!existsSync(this.walletDir)) {
      mkdirSync(this.walletDir, { recursive: true, mode: 0o700 });
    }
  }

  // ═══════════════════════ UI HELPERS ═══════════════════════

  clear() {
    console.clear();
  }

  header(title = "CARTEIRA RIVALE") {
    const width = 60;
    const padding = Math.max(0, Math.floor((width - title.length - 4) / 2));
    const line = "═".repeat(width);
    
    console.log(`\x1b[36m${line}\x1b[0m`);
    console.log(`\x1b[36m║\x1b[0m${" ".repeat(padding)}\x1b[1m⚡ ${title} ⚡\x1b[0m${" ".repeat(padding)}\x1b[36m║\x1b[0m`);
    console.log(`\x1b[36m${line}\x1b[0m\n`);
  }

  success(message) {
    console.log(`\x1b[32m✓ ${message}\x1b[0m`);
  }

  error(message) {
    console.log(`\x1b[31m✗ ${message}\x1b[0m`);
  }

  warning(message) {
    console.log(`\x1b[33m⚠ ${message}\x1b[0m`);
  }

  info(message) {
    console.log(`\x1b[34mℹ ${message}\x1b[0m`);
  }

  separator() {
    console.log(`\x1b[90m${"─".repeat(60)}\x1b[0m`);
  }

  async pause() {
    await inquirer.prompt([{
      type: 'input',
      name: 'continue',
      message: 'Pressione Enter para continuar...'
    }]);
  }

  formatBTC(amount) {
    return `\x1b[33m${amount.toFixed(8)} BTC\x1b[0m`;
  }

  formatAddress(address) {
    if (address.length > 20) {
      return `${address.slice(0, 8)}...${address.slice(-8)}`;
    }
    return address;
  }

  formatHash(hash) {
    return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
  }

  // ═══════════════════════ FILE ENCRYPTION ═══════════════════════

  encryptFile(data, password) {
    const salt = randomBytes(32);
    const iv = randomBytes(16);
    const key = pbkdf2Sync(password, salt, 100000, 32, 'sha256');

    const cipher = createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

    return Buffer.concat([salt, iv, encrypted]).toString('hex');
  }

  decryptFile(encryptedHex, password) {
    const encryptedBuffer = Buffer.from(encryptedHex, 'hex');
    const salt = encryptedBuffer.slice(0, 32);
    const iv = encryptedBuffer.slice(32, 48);
    const encrypted = encryptedBuffer.slice(48);

    const key = pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    return decrypted.toString('utf8');
  }

  // ═══════════════════════ BLOCKCHAIN API ═══════════════════════

  async getBalance(address, network = 'mainnet') {
    try {
      const url = network === 'mainnet' 
        ? `https://blockchain.info/q/addressbalance/${address}`
        : `https://blockstream.info/testnet/api/address/${address}/utxo`;
      
      const response = await axios.get(url, { timeout: 10000 });
      
      return network === 'mainnet' 
        ? response.data / 100000000
        : response.data.reduce((sum, utxo) => sum + utxo.value, 0) / 100000000;
    } catch (error) {
      this.error(`Falha ao buscar saldo: ${error.message}`);
      return 0;
    }
  }

  async getTransactions(address, network = 'mainnet') {
    try {
      const url = network === 'mainnet'
        ? `https://blockchain.info/rawaddr/${address}?limit=5`
        : `https://blockstream.info/testnet/api/address/${address}/txs`;
      
      const response = await axios.get(url, { timeout: 10000 });
      
      return network === 'mainnet'
        ? response.data.txs.slice(0, 5)
        : response.data.slice(0, 5);
    } catch (error) {
      this.error(`Falha ao buscar transações: ${error.message}`);
      return [];
    }
  }

  formatTransaction(tx, network) {
    if (network === 'mainnet') {
      return {
        hash: tx.hash,
        time: new Date(tx.time * 1000).toLocaleString(),
        amount: tx.result / 100000000
      };
    } else {
      return {
        hash: tx.txid,
        time: new Date(tx.status.block_time * 1000).toLocaleString(),
        amount: tx.vout.reduce((sum, output) => sum + output.value, 0) / 100000000
      };
    }
  }

  // ═══════════════════════ WALLET FILE OPERATIONS ═══════════════════════

  getWalletFilePath() {
    if (existsSync(this.walletFileEnc)) {
      return { path: this.walletFileEnc, encrypted: true };
    } else if (existsSync(this.walletFile)) {
      return { path: this.walletFile, encrypted: false };
    }
    return null;
  }

  async loadWallet() {
    const walletInfo = this.getWalletFilePath();
    if (!walletInfo) {
      this.error("Nenhuma carteira encontrada");
      return false;
    }

    try {
      let token;
      
      if (walletInfo.encrypted) {
        const { filePassword } = await inquirer.prompt([{
          type: 'password',
          name: 'filePassword',
          message: 'Senha de criptografia do arquivo:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        }]);

        const encryptedData = readFileSync(walletInfo.path, "utf8");
        token = this.decryptFile(encryptedData, filePassword);
      } else {
        token = readFileSync(walletInfo.path, "utf8");
      }

      const passwords = await inquirer.prompt([
        {
          type: 'password',
          name: 'password1',
          message: 'Primeira senha da carteira:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        },
        {
          type: 'password',
          name: 'password2',
          message: 'Segunda senha da carteira:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        }
      ]);
      
      this.currentWallet = await SFT.verifyToken(token, passwords.password1, passwords.password2, Buffer.from('ContextSaltTest'), 'high');
      
      this.success("Carteira carregada com sucesso");
      return true;
    } catch (error) {
      this.error("Senhas inválidas ou carteira corrompida");
      return false;
    }
  }

  async createWallet() {
    this.clear();
    this.header("CRIAR NOVA CARTEIRA");

    const walletConfig = await inquirer.prompt([
      {
        type: 'input',
        name: 'name',
        message: 'Nome da carteira:',
        validate: input => {
          if (!input) return "Nome da carteira obrigatório";
          if (input.length < 3) return "Nome da carteira deve ter pelo menos 3 caracteres";
          if (!/^[a-zA-Z0-9_-]+$/.test(input)) return "Apenas letras, números, _ e - permitidos";
          return true;
        }
      },
      {
        type: 'list',
        name: 'network',
        message: 'Rede:',
        choices: ['mainnet', 'testnet']
      }
    ]);

    console.log();
    this.warning("Escolha senhas fortes (8+ caracteres cada)");
    
    const passwords = await inquirer.prompt([
      {
        type: 'password',
        name: 'password1',
        message: 'Primeira senha da carteira:',
        validate: input => {
          if (!input) return "Senha obrigatória";
          if (input.length < 8) return "Senha deve ter pelo menos 8 caracteres";
          return true;
        }
      },
      {
        type: 'password',
        name: 'password2',
        message: 'Segunda senha da carteira:',
        validate: input => {
          if (!input) return "Senha obrigatória";
          if (input.length < 8) return "Senha deve ter pelo menos 8 caracteres";
          return true;
        }
      }
    ]);

    try {
      this.info("Gerando carteira...");
      
      const mnemonic = bip39.generateMnemonic();
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const root = bip32.fromSeed(seed, this.networks[walletConfig.network]);
      const path = `m/84'/${walletConfig.network === "mainnet" ? 0 : 1}'/0'/0/0`;
      const node = root.derivePath(path);

      const { address } = bitcoin.payments.p2wpkh({
        pubkey: Buffer.from(node.publicKey),
        network: this.networks[walletConfig.network],
      });

      const walletData = {
        private: {
          mnemonic,
          seed: seed.toString("hex"),
          privateKey: node.toWIF(),
          publicKey: Buffer.from(node.publicKey).toString("hex"),
          path,
          createdAt: new Date().toISOString(),
        },
        public: {
          name: walletConfig.name,
          network: walletConfig.network,
          address,
          xpub: root.neutered().toBase58(),
          createdAt: new Date().toISOString(),
        },
      };

      const token = await SFT.createToken(walletData, passwords.password1, passwords.password2, Buffer.from('ContextSaltTest'), 'high', null);
      
      // Pergunta se deseja criptografar o arquivo da carteira
      const { encryptFile } = await inquirer.prompt([{
        type: 'confirm',
        name: 'encryptFile',
        message: 'Deseja criptografar o arquivo da carteira? (Recomendado)',
        default: true
      }]);

      if (encryptFile) {
        const { filePassword } = await inquirer.prompt([{
          type: 'password',
          name: 'filePassword',
          message: 'Senha de criptografia do arquivo (terceira senha):',
          validate: input => {
            if (!input) return "Senha obrigatória";
            if (input.length < 8) return "Senha deve ter pelo menos 8 caracteres";
            return true;
          }
        }]);

        const encryptedData = this.encryptFile(token, filePassword);
        writeFileSync(this.walletFileEnc, encryptedData, { mode: 0o600 });
        this.success("Arquivo de carteira criptografado criado");
      } else {
        writeFileSync(this.walletFile, token, { mode: 0o600 });
        this.success("Arquivo de carteira criado");
      }

      this.currentWallet = walletData;
      
      console.log();
      this.success(`Carteira "${walletConfig.name}" criada com sucesso!`);
      this.info(`Rede: ${walletConfig.network}`);
      this.info(`Endereço: ${address}`);
      
      console.log();
      this.warning("IMPORTANTE: Salve sua frase de recuperação!");
      console.log(`\x1b[36m${mnemonic}\x1b[0m`);
      
      await this.pause();
    } catch (error) {
      this.error(`Falha ao criar carteira: ${error.message}`);
      await this.pause();
    }
  }

  async deleteWallet() {
    this.clear();
    this.header("EXCLUIR CARTEIRA");
    
    this.warning("Esta ação não pode ser desfeita!");
    
    const { confirmName } = await inquirer.prompt([{
      type: 'input',
      name: 'confirmName',
      message: `Digite "${this.currentWallet.public.name}" para confirmar:`,
      validate: input => input === this.currentWallet.public.name || "Nome da carteira não confere"
    }]);

    try {
      const passwords = await inquirer.prompt([
        {
          type: 'password',
          name: 'password1',
          message: 'Primeira senha da carteira:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        },
        {
          type: 'password',
          name: 'password2',
          message: 'Segunda senha da carteira:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        }
      ]);
      
      const walletInfo = this.getWalletFilePath();
      let token;
      
      if (walletInfo.encrypted) {
        const { filePassword } = await inquirer.prompt([{
          type: 'password',
          name: 'filePassword',
          message: 'Senha de criptografia do arquivo:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        }]);

        const encryptedData = readFileSync(walletInfo.path, "utf8");
        token = this.decryptFile(encryptedData, filePassword);
      } else {
        token = readFileSync(walletInfo.path, "utf8");
      }
      
      await SFT.verifyToken(token, passwords.password1, passwords.password2, Buffer.from('ContextSaltTest'), 'high');
      
      unlinkSync(walletInfo.path);
      this.currentWallet = null;
      
      this.success("Carteira excluída com sucesso");
      await this.pause();
    } catch (error) {
      this.error("Senhas inválidas");
      await this.pause();
    }
  }

  async backupWallet() {
    this.clear();
    this.header("BACKUP DA CARTEIRA");

    const walletInfo = this.getWalletFilePath();
    if (!walletInfo) {
      this.error("Nenhuma carteira encontrada");
      return await this.pause();
    }

    const { backupPath } = await inquirer.prompt([{
      type: 'input',
      name: 'backupPath',
      message: 'Caminho do arquivo de backup (sem extensão):',
      validate: input => input.length > 0 || 'Caminho obrigatório'
    }]);

    try {
      if (walletInfo.encrypted) {
        const passwords = await inquirer.prompt([
          {
            type: 'password',
            name: 'password1',
            message: 'Confirme a primeira senha da carteira:',
            validate: input => input.length > 0 || 'Senha obrigatória'
          },
          {
            type: 'password',
            name: 'password2',
            message: 'Confirme a segunda senha da carteira:',
            validate: input => input.length > 0 || 'Senha obrigatória'
          },
          {
            type: 'password',
            name: 'filePassword',
            message: 'Senha de criptografia do arquivo:',
            validate: input => input.length > 0 || 'Senha obrigatória'
          }
        ]);

        const encryptedData = readFileSync(walletInfo.path, "utf8");
        const token = this.decryptFile(encryptedData, passwords.filePassword);
        await SFT.verifyToken(token, passwords.password1, passwords.password2, Buffer.from('ContextSaltTest'), 'high');

        copyFileSync(walletInfo.path, `${backupPath}.secure.enc`);
        this.success(`Backup criptografado criado: ${backupPath}.secure.enc`);
      } else {
        // Para arquivos não criptografados, pede confirmação das senhas
        const passwords = await inquirer.prompt([
          {
            type: 'password',
            name: 'password1',
            message: 'Confirme a primeira senha da carteira:',
            validate: input => input.length > 0 || 'Senha obrigatória'
          },
          {
            type: 'password',
            name: 'password2',
            message: 'Confirme a segunda senha da carteira:',
            validate: input => input.length > 0 || 'Senha obrigatória'
          }
        ]);

        // Verifica as senhas
        const token = readFileSync(walletInfo.path, "utf8");
        await SFT.verifyToken(token, passwords.password1, passwords.password2, Buffer.from('ContextSaltTest'), 'high');

        copyFileSync(walletInfo.path, `${backupPath}.secure`);
        this.success(`Backup criado: ${backupPath}.secure`);
      }

      await this.pause();
    } catch (error) {
      this.error(`Falha no backup: ${error.message}`);
      await this.pause();
    }
  }

  async signTransaction() {
    this.clear();
    this.header("ASSINAR TRANSAÇÃO");

    const { psbtBase64 } = await inquirer.prompt([{
      type: 'input',
      name: 'psbtBase64',
      message: 'PSBT (base64):',
      validate: input => input.length > 0 || 'PSBT obrigatório'
    }]);

    try {
      const passwords = await inquirer.prompt([
        {
          type: 'password',
          name: 'password1',
          message: 'Primeira senha da carteira:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        },
        {
          type: 'password',
          name: 'password2',
          message: 'Segunda senha da carteira:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        }
      ]);
      
      // Verifica as senhas descriptografando
      const walletInfo = this.getWalletFilePath();
      let token;
      
      if (walletInfo.encrypted) {
        const { filePassword } = await inquirer.prompt([{
          type: 'password',
          name: 'filePassword',
          message: 'Senha de criptografia do arquivo:',
          validate: input => input.length > 0 || 'Senha obrigatória'
        }]);

        const encryptedData = readFileSync(walletInfo.path, "utf8");
        token = this.decryptFile(encryptedData, filePassword);
      } else {
        token = readFileSync(walletInfo.path, "utf8");
      }
      
      const walletData = await SFT.verifyToken(token, passwords.password1, passwords.password2, Buffer.from('ContextSaltTest'), 'high');
      
      const network = this.networks[walletData.public.network];
      const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network });
      const keyPair = bitcoin.ECPair.fromWIF(walletData.private.privateKey, network);

      psbt.signAllInputs(keyPair);
      psbt.finalizeAllInputs();
      const rawTx = psbt.extractTransaction().toHex();
      
      console.log();
      this.success("Transação assinada com sucesso!");
      this.separator();
      console.log("Transação bruta:");
      console.log(`\x1b[36m${rawTx}\x1b[0m`);
      
      await this.pause();
    } catch (error) {
      this.error(`Falha ao assinar transação: ${error.message}`);
      await this.pause();
    }
  }

  // ═══════════════════════ SCREENS ═══════════════════════

  async showMainMenu() {
    const walletInfo = this.getWalletFilePath();
    
    if (!this.currentWallet && walletInfo) {
      const loaded = await this.loadWallet();
      if (!loaded) return;
    }

    while (true) {
      this.clear();
      this.header();

      if (this.currentWallet) {
        await this.showDashboard();
      } else {
        const { choice } = await inquirer.prompt([{
          type: 'list',
          name: 'choice',
          message: 'Escolha uma opção:',
          choices: [
            { name: 'Criar nova carteira', value: 'create' },
            { name: 'Carregar carteira existente', value: 'load' },
            { name: 'Sair', value: 'exit' }
          ]
        }]);

        switch (choice) {
          case 'create': await this.createWallet(); break;
          case 'load': await this.loadWallet(); break;
          case 'exit': this.exit(); break;
        }
      }
    }
  }

  async showDashboard() {
    const { name, network, address } = this.currentWallet.public;
    
    this.info(`Carteira: ${name} (${network})`);
    this.info(`Endereço: ${address}`);
    
    console.log();
    this.info("Buscando saldo e transações...");
    
    const [balance, transactions] = await Promise.all([
      this.getBalance(address, network),
      this.getTransactions(address, network)
    ]);

    console.log(`Saldo: ${this.formatBTC(balance)}`);
    
    this.separator();
    console.log("Transações recentes:");
    
    if (transactions.length === 0) {
      console.log("  Nenhuma transação encontrada");
    } else {
      transactions.forEach(tx => {
        const formatted = this.formatTransaction(tx, network);
        console.log(`  ${formatted.time} | ${this.formatHash(formatted.hash)} | ${this.formatBTC(formatted.amount)}`);
      });
    }
    
    this.separator();

    const { choice } = await inquirer.prompt([{
      type: 'list',
      name: 'choice',
      message: 'Escolha uma opção:',
      choices: [
        { name: 'Atualizar', value: 'refresh' },
        { name: 'Assinar transação', value: 'sign' },
        { name: 'Backup da carteira', value: 'backup' },
        { name: 'Excluir carteira', value: 'delete' },
        { name: 'Logout', value: 'logout' }
      ]
    }]);

    switch (choice) {
      case 'refresh': break; // Apenas continua o loop
      case 'sign': await this.signTransaction(); break;
      case 'backup': await this.backupWallet(); break;
      case 'delete': 
        await this.deleteWallet();
        if (!this.currentWallet) return; // Volta ao menu principal
        break;
      case 'logout': 
        this.currentWallet = null;
        return; // Volta ao menu principal
    }
  }

  exit() {
    this.clear();
    console.log("\x1b[36m👋 Até logo!\x1b[0m\n");
    process.exit(0);
  }

  async run() {
    try {
      await this.showMainMenu();
    } catch (error) {
      this.error(`Erro fatal: ${error.message}`);
      this.exit();
    }
  }
}

// ═══════════════════════ STARTUP ═══════════════════════

const cli = new BitcoinWalletCLI();
  
process.on('SIGINT', () => {
  console.log('\n\x1b[36m👋 Até logo!\x1b[0m');
  process.exit(0);
});

cli.run();
