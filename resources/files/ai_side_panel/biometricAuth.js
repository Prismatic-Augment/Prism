// Biometric Authentication Module - Fingerprint/Face ID support

import passwordManager from './passwordManager.js';

class BiometricAuthManager {
  constructor() {
    this.isSupported = false;
    this.isEnabled = false;
    this.authTimeout = 300000; // 5 minutes
    this.lastAuthTime = null;
    this.checkSupport();
  }

  // Check if WebAuthn is supported
  async checkSupport() {
    this.isSupported = !!(
      window.PublicKeyCredential &&
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
    );

    if (this.isSupported) {
      try {
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        this.isSupported = available;
      } catch (error) {
        console.error('Error checking biometric support:', error);
        this.isSupported = false;
      }
    }

    // Check if enabled in settings
    const settings = await chrome.storage.local.get('biometricSettings');
    this.isEnabled = settings.biometricSettings?.enabled || false;

    return this.isSupported;
  }

  // Enable biometric authentication
  async enableBiometric(masterPassword) {
    if (!this.isSupported) {
      throw new Error('Biometric authentication not supported on this device');
    }

    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    try {
      // Generate challenge
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      
      // Create credential
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: challenge,
          rp: {
            name: 'BrowserOS Password Manager',
            id: window.location.hostname
          },
          user: {
            id: new TextEncoder().encode('password-manager-user'),
            name: 'password-manager',
            displayName: 'Password Manager User'
          },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },  // ES256
            { alg: -257, type: 'public-key' } // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required'
          },
          timeout: 60000,
          attestation: 'none'
        }
      });

      // Store credential ID and encrypted master password
      const encryptedMasterPassword = await this.encryptWithBiometric(
        masterPassword,
        credential.rawId
      );

      const biometricData = {
        enabled: true,
        credentialId: Array.from(new Uint8Array(credential.rawId)),
        publicKey: Array.from(new Uint8Array(credential.response.publicKey)),
        encryptedMasterPassword: encryptedMasterPassword,
        enabledAt: Date.now(),
        algorithm: credential.response.getPublicKeyAlgorithm()
      };

      await chrome.storage.local.set({ 
        biometricSettings: biometricData 
      });

      this.isEnabled = true;

      return {
        success: true,
        credentialId: credential.id
      };

    } catch (error) {
      console.error('Error enabling biometric:', error);
      throw new Error(`Failed to enable biometric authentication: ${error.message}`);
    }
  }

  // Disable biometric authentication
  async disableBiometric() {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    await chrome.storage.local.remove('biometricSettings');
    this.isEnabled = false;

    return { success: true };
  }

  // Authenticate with biometric
  async authenticate() {
    if (!this.isEnabled) {
      throw new Error('Biometric authentication not enabled');
    }

    // Check if recently authenticated
    if (this.lastAuthTime && Date.now() - this.lastAuthTime < this.authTimeout) {
      return {
        success: true,
        cached: true
      };
    }

    const settings = await chrome.storage.local.get('biometricSettings');
    const biometricData = settings.biometricSettings;

    if (!biometricData) {
      throw new Error('Biometric data not found');
    }

    try {
      // Generate challenge
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      // Request biometric authentication
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          allowCredentials: [{
            id: new Uint8Array(biometricData.credentialId),
            type: 'public-key',
            transports: ['internal']
          }],
          userVerification: 'required',
          timeout: 60000
        }
      });

      // Verify the assertion (in production, this would be done server-side)
      const verified = await this.verifyAssertion(assertion, biometricData);

      if (verified) {
        this.lastAuthTime = Date.now();

        // Decrypt master password
        const masterPassword = await this.decryptWithBiometric(
          biometricData.encryptedMasterPassword,
          assertion.rawId
        );

        return {
          success: true,
          masterPassword: masterPassword
        };
      }

      throw new Error('Biometric verification failed');

    } catch (error) {
      console.error('Biometric authentication error:', error);
      throw new Error(`Authentication failed: ${error.message}`);
    }
  }

  // Quick unlock with biometric
  async quickUnlock() {
    if (!this.isEnabled) {
      throw new Error('Biometric authentication not enabled');
    }

    try {
      const result = await this.authenticate();
      
      if (result.success && result.masterPassword) {
        // Unlock password manager with decrypted master password
        const unlocked = await passwordManager.unlock(result.masterPassword);
        
        if (unlocked) {
          return {
            success: true,
            method: 'biometric'
          };
        }
      }

      throw new Error('Failed to unlock with biometric');

    } catch (error) {
      console.error('Quick unlock error:', error);
      throw error;
    }
  }

  // Encrypt data with biometric-derived key
  async encryptWithBiometric(data, credentialId) {
    // Derive key from credential ID
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      credentialId,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: new TextEncoder().encode('biometric-salt'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      new TextEncoder().encode(data)
    );

    return {
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(encrypted))
    };
  }

  // Decrypt data with biometric-derived key
  async decryptWithBiometric(encryptedData, credentialId) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      credentialId,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: new TextEncoder().encode('biometric-salt'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encryptedData.iv) },
      key,
      new Uint8Array(encryptedData.data)
    );

    return new TextDecoder().decode(decrypted);
  }

  // Verify assertion (simplified - in production would verify signature)
  async verifyAssertion(assertion, biometricData) {
    // Basic verification - check credential ID matches
    const credentialIdMatch = Array.from(new Uint8Array(assertion.rawId))
      .every((val, index) => val === biometricData.credentialId[index]);

    return credentialIdMatch;
  }

  // Get biometric status
  async getStatus() {
    await this.checkSupport();

    const settings = await chrome.storage.local.get('biometricSettings');
    const biometricData = settings.biometricSettings;

    return {
      supported: this.isSupported,
      enabled: this.isEnabled,
      lastAuth: this.lastAuthTime ? new Date(this.lastAuthTime) : null,
      enrolledAt: biometricData?.enabledAt ? new Date(biometricData.enabledAt) : null,
      authTimeout: this.authTimeout,
      platformAuth: await this.getPlatformAuthenticator()
    };
  }

  // Get platform authenticator info
  async getPlatformAuthenticator() {
    if (!this.isSupported) return null;

    try {
      // Check for specific biometric types (when API supports it)
      const info = {
        type: 'platform',
        userVerification: 'required'
      };

      // Try to detect biometric type
      if (navigator.userAgent.includes('Mac')) {
        info.biometricType = 'Touch ID';
      } else if (navigator.userAgent.includes('Windows')) {
        info.biometricType = 'Windows Hello';
      } else if (navigator.userAgent.includes('Android')) {
        info.biometricType = 'Fingerprint/Face';
      } else if (navigator.userAgent.includes('iPhone') || navigator.userAgent.includes('iPad')) {
        info.biometricType = 'Touch ID/Face ID';
      } else {
        info.biometricType = 'Platform Biometric';
      }

      return info;
    } catch (error) {
      return null;
    }
  }

  // Re-authenticate for sensitive operations
  async reAuthenticate(reason = 'perform this action') {
    if (!this.isEnabled) {
      throw new Error('Biometric authentication not enabled');
    }

    // Force fresh authentication
    this.lastAuthTime = null;

    const modal = this.showAuthModal(reason);

    try {
      const result = await this.authenticate();
      modal.remove();
      return result;
    } catch (error) {
      modal.remove();
      throw error;
    }
  }

  // Show authentication modal
  showAuthModal(reason) {
    const modal = document.createElement('div');
    modal.className = 'biometric-auth-modal';
    modal.innerHTML = `
      <div class="biometric-auth-content">
        <div class="biometric-icon">🔐</div>
        <h3>Authentication Required</h3>
        <p>Please authenticate to ${reason}</p>
        <div class="biometric-spinner"></div>
        <button class="cancel-auth">Cancel</button>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelector('.cancel-auth').addEventListener('click', () => {
      modal.remove();
    });

    return modal;
  }

  // Handle authentication errors
  handleAuthError(error) {
    const errorMessages = {
      'NotAllowedError': 'Authentication was cancelled or not allowed',
      'NotSupportedError': 'This device does not support biometric authentication',
      'InvalidStateError': 'Authentication is in an invalid state',
      'SecurityError': 'Authentication failed due to security restrictions',
      'AbortError': 'Authentication was aborted',
      'NetworkError': 'Network error during authentication',
      'UnknownError': 'An unknown error occurred'
    };

    return errorMessages[error.name] || error.message || 'Authentication failed';
  }

  // Listen for lock events to clear auth cache
  setupEventListeners() {
    // Clear auth cache when password manager locks
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'passwordManagerLocked') {
        this.lastAuthTime = null;
      }
    });

    // Clear auth cache on visibility change
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        // Clear auth cache when page becomes hidden
        setTimeout(() => {
          if (document.hidden) {
            this.lastAuthTime = null;
          }
        }, 60000); // 1 minute
      }
    });
  }
}

// Export singleton instance
const biometricAuthManager = new BiometricAuthManager();
biometricAuthManager.setupEventListeners();

export default biometricAuthManager;