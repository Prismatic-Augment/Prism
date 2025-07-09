// Password Manager Module with Encryption
class PasswordManager {
  constructor() {
    this.masterKey = null;
    this.isUnlocked = false;
    this.lockTimeout = 5 * 60 * 1000; // 5 minutes
    this.lockTimer = null;
  }

  // Generate a random salt for key derivation
  generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  // Derive encryption key from master password
  async deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Initialize with master password
  async unlock(masterPassword) {
    try {
      const storedData = await chrome.storage.local.get(['passwordSalt', 'passwordVerifier']);
      
      if (!storedData.passwordSalt) {
        // First time setup
        const salt = this.generateSalt();
        this.masterKey = await this.deriveKey(masterPassword, salt);
        
        // Create a verifier to check password validity
        const verifier = await this.encrypt('password_verifier', this.masterKey);
        
        await chrome.storage.local.set({
          passwordSalt: Array.from(salt),
          passwordVerifier: verifier
        });
      } else {
        // Verify existing password
        const salt = new Uint8Array(storedData.passwordSalt);
        this.masterKey = await this.deriveKey(masterPassword, salt);
        
        try {
          const decrypted = await this.decrypt(storedData.passwordVerifier, this.masterKey);
          if (decrypted !== 'password_verifier') {
            throw new Error('Invalid master password');
          }
        } catch (error) {
          this.masterKey = null;
          throw new Error('Invalid master password');
        }
      }

      this.isUnlocked = true;
      this.resetLockTimer();
      return true;
    } catch (error) {
      console.error('Unlock error:', error);
      throw error;
    }
  }

  // Lock the password manager
  lock() {
    this.masterKey = null;
    this.isUnlocked = false;
    if (this.lockTimer) {
      clearTimeout(this.lockTimer);
      this.lockTimer = null;
    }
  }

  // Reset auto-lock timer
  resetLockTimer() {
    if (this.lockTimer) {
      clearTimeout(this.lockTimer);
    }
    this.lockTimer = setTimeout(() => this.lock(), this.lockTimeout);
  }

  // Encrypt data
  async encrypt(data, key = this.masterKey) {
    if (!key) throw new Error('Password manager is locked');
    
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(data));
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encodedData
    );

    return {
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(encryptedData))
    };
  }

  // Decrypt data
  async decrypt(encryptedObj, key = this.masterKey) {
    if (!key) throw new Error('Password manager is locked');
    
    const iv = new Uint8Array(encryptedObj.iv);
    const data = new Uint8Array(encryptedObj.data);
    
    const decryptedData = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      data
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedData));
  }

  // Save credential
  async saveCredential(credential) {
    if (!this.isUnlocked) throw new Error('Password manager is locked');
    
    this.resetLockTimer();
    
    const encryptedCredential = await this.encrypt(credential);
    const credentials = await this.getAllCredentials();
    
    // Check if credential already exists
    const existingIndex = credentials.findIndex(
      c => c.domain === credential.domain && c.username === credential.username
    );

    if (existingIndex >= 0) {
      credentials[existingIndex] = {
        id: credentials[existingIndex].id,
        domain: credential.domain,
        username: credential.username,
        encrypted: encryptedCredential,
        lastModified: Date.now()
      };
    } else {
      credentials.push({
        id: crypto.randomUUID(),
        domain: credential.domain,
        username: credential.username,
        encrypted: encryptedCredential,
        lastModified: Date.now()
      });
    }

    await chrome.storage.local.set({ credentials });
    return true;
  }

  // Get all credentials (encrypted)
  async getAllCredentials() {
    const data = await chrome.storage.local.get('credentials');
    return data.credentials || [];
  }

  // Get credentials for a domain
  async getCredentialsForDomain(domain) {
    if (!this.isUnlocked) throw new Error('Password manager is locked');
    
    this.resetLockTimer();
    
    const credentials = await this.getAllCredentials();
    const domainCredentials = [];

    for (const cred of credentials) {
      if (cred.domain === domain || this.isDomainMatch(domain, cred.domain)) {
        try {
          const decrypted = await this.decrypt(cred.encrypted);
          domainCredentials.push({
            id: cred.id,
            domain: cred.domain,
            username: decrypted.username,
            password: decrypted.password,
            lastModified: cred.lastModified
          });
        } catch (error) {
          console.error('Failed to decrypt credential:', error);
        }
      }
    }

    return domainCredentials;
  }

  // Check if domains match (including subdomains)
  isDomainMatch(url, savedDomain) {
    try {
      const urlDomain = new URL(url).hostname;
      const saved = new URL(savedDomain).hostname;
      
      // Exact match
      if (urlDomain === saved) return true;
      
      // Subdomain match
      if (urlDomain.endsWith('.' + saved)) return true;
      
      return false;
    } catch {
      return false;
    }
  }

  // Delete credential
  async deleteCredential(id) {
    if (!this.isUnlocked) throw new Error('Password manager is locked');
    
    this.resetLockTimer();
    
    const credentials = await this.getAllCredentials();
    const filtered = credentials.filter(c => c.id !== id);
    
    await chrome.storage.local.set({ credentials: filtered });
    return true;
  }

  // Generate strong password
  generatePassword(length = 20, options = {}) {
    const {
      includeUppercase = true,
      includeLowercase = true,
      includeNumbers = true,
      includeSymbols = true,
      excludeSimilar = true
    } = options;

    let charset = '';
    if (includeLowercase) charset += excludeSimilar ? 'abcdefghijkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    if (includeUppercase) charset += excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeNumbers) charset += excludeSimilar ? '23456789' : '0123456789';
    if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) throw new Error('At least one character type must be selected');

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }

    return password;
  }

  // Check password strength
  checkPasswordStrength(password) {
    let strength = 0;
    const feedback = [];

    if (password.length >= 12) strength += 20;
    else if (password.length >= 8) strength += 10;
    else feedback.push('Password should be at least 8 characters');

    if (/[a-z]/.test(password)) strength += 20;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) strength += 20;
    else feedback.push('Add uppercase letters');

    if (/[0-9]/.test(password)) strength += 20;
    else feedback.push('Add numbers');

    if (/[^a-zA-Z0-9]/.test(password)) strength += 20;
    else feedback.push('Add special characters');

    // Check for common patterns
    if (/(.)\1{2,}/.test(password)) {
      strength -= 10;
      feedback.push('Avoid repeated characters');
    }

    if (/^(password|12345|qwerty)/i.test(password)) {
      strength = 0;
      feedback.push('Avoid common passwords');
    }

    return {
      score: Math.max(0, Math.min(100, strength)),
      feedback,
      level: strength >= 80 ? 'strong' : strength >= 60 ? 'good' : strength >= 40 ? 'fair' : 'weak'
    };
  }

  // Export credentials (encrypted)
  async exportCredentials() {
    if (!this.isUnlocked) throw new Error('Password manager is locked');
    
    const credentials = await this.getAllCredentials();
    const salt = await chrome.storage.local.get('passwordSalt');
    
    return {
      version: '1.0',
      salt: salt.passwordSalt,
      credentials: credentials,
      exported: new Date().toISOString()
    };
  }

  // Import credentials
  async importCredentials(data, masterPassword) {
    if (!data.version || !data.salt || !data.credentials) {
      throw new Error('Invalid import data format');
    }

    // Verify the master password with the imported salt
    const importKey = await this.deriveKey(masterPassword, new Uint8Array(data.salt));
    
    // Try to decrypt first credential to verify password
    if (data.credentials.length > 0) {
      try {
        await this.decrypt(data.credentials[0].encrypted, importKey);
      } catch {
        throw new Error('Invalid master password for import data');
      }
    }

    // Import credentials
    const existingCredentials = await this.getAllCredentials();
    const mergedCredentials = [...existingCredentials, ...data.credentials];
    
    await chrome.storage.local.set({ credentials: mergedCredentials });
    return mergedCredentials.length;
  }
}

// Export as singleton
const passwordManager = new PasswordManager();
export default passwordManager;