// WebAuthn/FIDO2 Module - Passwordless authentication support

import passwordManager from './passwordManager.js';

class WebAuthnManager {
  constructor() {
    this.rpName = 'BrowserOS Password Manager';
    this.rpId = window.location.hostname;
    this.credentials = new Map();
    this.isSupported = this.checkSupport();
  }

  // Check WebAuthn support
  checkSupport() {
    return !!(
      window.PublicKeyCredential &&
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
      window.PublicKeyCredential.isConditionalMediationAvailable
    );
  }

  // Register a new WebAuthn credential
  async registerCredential(options = {}) {
    if (!this.isSupported) {
      throw new Error('WebAuthn not supported on this device');
    }

    const user = {
      id: new TextEncoder().encode(options.userId || crypto.randomUUID()),
      name: options.username || 'user@example.com',
      displayName: options.displayName || 'Password Manager User'
    };

    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const publicKeyCredentialCreationOptions = {
      challenge,
      rp: {
        name: this.rpName,
        id: this.rpId
      },
      user,
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256
        { alg: -257, type: 'public-key' }, // RS256
        { alg: -8, type: 'public-key' }    // EdDSA
      ],
      authenticatorSelection: {
        authenticatorAttachment: options.authenticatorType || 'cross-platform',
        userVerification: options.userVerification || 'preferred',
        residentKey: options.residentKey || 'preferred',
        requireResidentKey: options.requireResidentKey || false
      },
      timeout: 60000,
      attestation: options.attestation || 'direct',
      extensions: {
        credProps: true,
        largeBlob: {
          support: 'preferred'
        },
        credentialProtectionPolicy: 'userVerificationOptional',
        enforceCredentialProtectionPolicy: false
      }
    };

    try {
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });

      // Parse and store credential
      const credentialData = {
        id: credential.id,
        rawId: Array.from(new Uint8Array(credential.rawId)),
        type: credential.type,
        response: {
          attestationObject: Array.from(new Uint8Array(credential.response.attestationObject)),
          clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
          publicKey: await this.extractPublicKey(credential.response)
        },
        extensions: credential.getClientExtensionResults(),
        user: user,
        createdAt: Date.now(),
        lastUsed: null,
        counter: 0,
        backupEligible: credential.response.getAuthenticatorData?.().backupEligible || false,
        backupState: credential.response.getAuthenticatorData?.().backupState || false
      };

      // Store credential
      await this.storeCredential(credentialData);

      // Link to password manager if requested
      if (options.linkToPasswordManager) {
        await this.linkToPasswordManager(credentialData.id);
      }

      return {
        success: true,
        credentialId: credential.id,
        publicKey: credentialData.response.publicKey,
        attestation: await this.verifyAttestation(credential.response)
      };

    } catch (error) {
      console.error('WebAuthn registration error:', error);
      throw new Error(`Failed to register credential: ${error.message}`);
    }
  }

  // Authenticate with WebAuthn
  async authenticate(options = {}) {
    if (!this.isSupported) {
      throw new Error('WebAuthn not supported on this device');
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    
    // Get stored credentials
    const storedCredentials = await this.getStoredCredentials();
    const allowCredentials = options.credentialId 
      ? [{ 
          id: new Uint8Array(storedCredentials.find(c => c.id === options.credentialId).rawId),
          type: 'public-key',
          transports: ['internal', 'usb', 'nfc', 'ble']
        }]
      : storedCredentials.map(cred => ({
          id: new Uint8Array(cred.rawId),
          type: 'public-key',
          transports: ['internal', 'usb', 'nfc', 'ble']
        }));

    const publicKeyCredentialRequestOptions = {
      challenge,
      allowCredentials,
      timeout: 60000,
      userVerification: options.userVerification || 'preferred',
      rpId: this.rpId,
      extensions: {
        largeBlob: {
          read: true
        },
        getCredProps: true
      }
    };

    try {
      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
        mediation: options.conditional ? 'conditional' : 'optional'
      });

      // Verify assertion
      const verified = await this.verifyAssertion(assertion, challenge);

      if (verified) {
        // Update credential usage
        await this.updateCredentialUsage(assertion.id);

        // Unlock password manager if linked
        if (options.unlockPasswordManager) {
          await this.unlockWithWebAuthn(assertion);
        }

        return {
          success: true,
          credentialId: assertion.id,
          userHandle: assertion.response.userHandle 
            ? new TextDecoder().decode(assertion.response.userHandle)
            : null,
          extensions: assertion.getClientExtensionResults()
        };
      }

      throw new Error('Assertion verification failed');

    } catch (error) {
      console.error('WebAuthn authentication error:', error);
      throw new Error(`Authentication failed: ${error.message}`);
    }
  }

  // Conditional UI authentication (autofill)
  async setupConditionalUI() {
    if (!this.isSupported) return;

    try {
      const available = await PublicKeyCredential.isConditionalMediationAvailable();
      if (!available) return;

      // Add conditional UI to all password fields
      const passwordFields = document.querySelectorAll('input[type="password"]');
      
      passwordFields.forEach(field => {
        field.setAttribute('autocomplete', 'current-password webauthn');
        
        // Listen for focus to trigger conditional UI
        field.addEventListener('focus', async () => {
          try {
            const result = await this.authenticate({
              conditional: true,
              unlockPasswordManager: true
            });

            if (result.success) {
              // Auto-fill credentials
              const event = new CustomEvent('webauthn-authenticated', {
                detail: result
              });
              field.dispatchEvent(event);
            }
          } catch (error) {
            // Conditional UI cancelled or failed silently
          }
        });
      });

    } catch (error) {
      console.error('Conditional UI setup error:', error);
    }
  }

  // Link WebAuthn credential to password manager
  async linkToPasswordManager(credentialId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    const linkData = {
      credentialId,
      linkedAt: Date.now(),
      type: 'webauthn'
    };

    await chrome.storage.local.set({ 
      webauthnLink: linkData 
    });

    return { success: true };
  }

  // Unlock password manager with WebAuthn
  async unlockWithWebAuthn(assertion) {
    const link = await chrome.storage.local.get('webauthnLink');
    
    if (!link.webauthnLink || link.webauthnLink.credentialId !== assertion.id) {
      throw new Error('WebAuthn credential not linked to password manager');
    }

    // Derive unlock key from assertion
    const unlockKey = await this.deriveUnlockKey(assertion);
    
    // Retrieve encrypted master password
    const encryptedMaster = await chrome.storage.local.get('webauthnMasterPassword');
    
    if (!encryptedMaster.webauthnMasterPassword) {
      throw new Error('Master password not found for WebAuthn unlock');
    }

    // Decrypt master password
    const masterPassword = await this.decryptWithKey(
      encryptedMaster.webauthnMasterPassword,
      unlockKey
    );

    // Unlock password manager
    const unlocked = await passwordManager.unlock(masterPassword);

    return { success: unlocked };
  }

  // Store WebAuthn master password
  async storeWebAuthnMasterPassword(masterPassword, credentialId) {
    const credential = await this.getCredential(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }

    // Derive storage key from credential
    const storageKey = await this.deriveStorageKey(credential);

    // Encrypt master password
    const encrypted = await this.encryptWithKey(masterPassword, storageKey);

    await chrome.storage.local.set({
      webauthnMasterPassword: encrypted
    });

    return { success: true };
  }

  // Extract public key from attestation
  async extractPublicKey(response) {
    const attestationObject = response.attestationObject;
    // Parse CBOR to extract public key
    // Simplified - in production use proper CBOR parser
    return Array.from(new Uint8Array(attestationObject.slice(0, 65)));
  }

  // Verify attestation
  async verifyAttestation(response) {
    // In production, implement full attestation verification
    // For now, return basic verification
    return {
      verified: true,
      format: 'none',
      trustPath: []
    };
  }

  // Verify assertion
  async verifyAssertion(assertion, challenge) {
    const credential = await this.getCredential(assertion.id);
    if (!credential) {
      throw new Error('Credential not found');
    }

    // Verify challenge
    const clientDataJSON = JSON.parse(
      new TextDecoder().decode(assertion.response.clientDataJSON)
    );

    const challengeMatch = btoa(String.fromCharCode(...challenge)) === clientDataJSON.challenge;
    
    if (!challengeMatch) {
      throw new Error('Challenge mismatch');
    }

    // Verify signature (simplified)
    // In production, implement full signature verification
    return true;
  }

  // Store credential
  async storeCredential(credentialData) {
    const credentials = await this.getStoredCredentials();
    
    // Check if credential already exists
    const existingIndex = credentials.findIndex(c => c.id === credentialData.id);
    
    if (existingIndex >= 0) {
      credentials[existingIndex] = credentialData;
    } else {
      credentials.push(credentialData);
    }

    await chrome.storage.local.set({ webauthnCredentials: credentials });
  }

  // Get stored credentials
  async getStoredCredentials() {
    const data = await chrome.storage.local.get('webauthnCredentials');
    return data.webauthnCredentials || [];
  }

  // Get specific credential
  async getCredential(credentialId) {
    const credentials = await this.getStoredCredentials();
    return credentials.find(c => c.id === credentialId);
  }

  // Update credential usage
  async updateCredentialUsage(credentialId) {
    const credentials = await this.getStoredCredentials();
    const credential = credentials.find(c => c.id === credentialId);
    
    if (credential) {
      credential.lastUsed = Date.now();
      credential.counter++;
      await chrome.storage.local.set({ webauthnCredentials: credentials });
    }
  }

  // Delete credential
  async deleteCredential(credentialId) {
    const credentials = await this.getStoredCredentials();
    const filtered = credentials.filter(c => c.id !== credentialId);
    
    await chrome.storage.local.set({ webauthnCredentials: filtered });
    
    // Remove link if exists
    const link = await chrome.storage.local.get('webauthnLink');
    if (link.webauthnLink?.credentialId === credentialId) {
      await chrome.storage.local.remove('webauthnLink');
    }

    return { success: true };
  }

  // Derive unlock key from assertion
  async deriveUnlockKey(assertion) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      assertion.response.authenticatorData,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: new TextEncoder().encode('webauthn-unlock'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  // Derive storage key from credential
  async deriveStorageKey(credential) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(credential.response.publicKey),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: new TextEncoder().encode('webauthn-storage'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Encrypt with key
  async encryptWithKey(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(data)
    );

    return {
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(encrypted))
    };
  }

  // Decrypt with key
  async decryptWithKey(encrypted, key) {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
      key,
      new Uint8Array(encrypted.data)
    );

    return new TextDecoder().decode(decrypted);
  }

  // Get WebAuthn status
  async getStatus() {
    const supported = await this.checkSupport();
    const credentials = await this.getStoredCredentials();
    const link = await chrome.storage.local.get('webauthnLink');
    const conditionalUI = await PublicKeyCredential.isConditionalMediationAvailable?.() || false;

    return {
      supported,
      conditionalUIAvailable: conditionalUI,
      credentials: credentials.map(c => ({
        id: c.id,
        createdAt: new Date(c.createdAt),
        lastUsed: c.lastUsed ? new Date(c.lastUsed) : null,
        counter: c.counter,
        backupEligible: c.backupEligible,
        user: c.user.displayName
      })),
      linkedToPasswordManager: !!link.webauthnLink,
      platformAuthenticator: await this.checkPlatformAuthenticator()
    };
  }

  // Check for platform authenticator
  async checkPlatformAuthenticator() {
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  // Export credential for backup
  async exportCredential(credentialId) {
    const credential = await this.getCredential(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }

    // Remove sensitive data
    const exportData = {
      id: credential.id,
      user: credential.user,
      createdAt: credential.createdAt,
      backupEligible: credential.backupEligible
    };

    return {
      version: '1.0',
      type: 'webauthn_backup',
      credential: exportData,
      exported: new Date().toISOString()
    };
  }
}

// Export singleton instance
const webAuthnManager = new WebAuthnManager();

// Auto-setup conditional UI when loaded
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    webAuthnManager.setupConditionalUI();
  });
}

export default webAuthnManager;