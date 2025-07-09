// Password Sharing Module - Secure credential sharing with audit trail

import passwordManager from './passwordManager.js';

class PasswordSharingManager {
  constructor() {
    this.shareExpiryDefault = 24 * 60 * 60 * 1000; // 24 hours
    this.maxSharesPerCredential = 10;
    this.publicKeyCache = new Map();
  }

  // Share a credential with another user
  async shareCredential(credentialId, shareData) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    const credentials = await passwordManager.getAllCredentials();
    const credential = credentials.find(c => c.id === credentialId);

    if (!credential) {
      throw new Error('Credential not found');
    }

    // Get recipient's public key
    const recipientPublicKey = await this.getRecipientPublicKey(shareData.recipientEmail);

    if (!recipientPublicKey) {
      throw new Error('Recipient not found or not registered');
    }

    // Create share token
    const shareToken = {
      id: crypto.randomUUID(),
      credentialId: credentialId,
      sharedBy: await this.getCurrentUserEmail(),
      sharedWith: shareData.recipientEmail,
      permissions: shareData.permissions || 'view', // view, use, edit
      expiresAt: Date.now() + (shareData.expiryTime || this.shareExpiryDefault),
      createdAt: Date.now(),
      maxUses: shareData.maxUses || null,
      uses: 0,
      notes: shareData.notes || '',
      requiresApproval: shareData.requiresApproval || false,
      approved: !shareData.requiresApproval
    };

    // Decrypt credential
    const decrypted = await passwordManager.decrypt(credential.encrypted);

    // Prepare shared data based on permissions
    const sharedData = {
      domain: credential.domain,
      favicon: credential.favicon,
      tags: credential.tags
    };

    if (shareToken.permissions === 'view' || shareToken.permissions === 'use' || shareToken.permissions === 'edit') {
      sharedData.username = decrypted.username;
      sharedData.password = decrypted.password;
    }

    if (shareToken.permissions === 'use' || shareToken.permissions === 'edit') {
      sharedData.notes = decrypted.notes;
    }

    // Encrypt shared data with recipient's public key
    const encryptedShare = await this.encryptForRecipient(sharedData, recipientPublicKey);

    // Store share record
    const shares = await this.getShares();
    shares.push({
      ...shareToken,
      encryptedData: encryptedShare
    });

    await chrome.storage.local.set({ passwordShares: shares });

    // Add to audit log
    await this.addAuditEntry({
      action: 'share_created',
      credentialId: credentialId,
      shareId: shareToken.id,
      recipient: shareData.recipientEmail,
      permissions: shareToken.permissions,
      expiresAt: shareToken.expiresAt
    });

    // Send notification to recipient
    await this.notifyRecipient(shareToken, credential.domain);

    return {
      shareId: shareToken.id,
      shareUrl: await this.generateShareUrl(shareToken.id),
      expiresAt: new Date(shareToken.expiresAt)
    };
  }

  // Accept a shared credential
  async acceptShare(shareId, acceptData) {
    const shares = await this.getShares();
    const share = shares.find(s => s.id === shareId);

    if (!share) {
      throw new Error('Share not found');
    }

    if (share.expiresAt < Date.now()) {
      throw new Error('Share has expired');
    }

    if (share.maxUses && share.uses >= share.maxUses) {
      throw new Error('Share has reached maximum uses');
    }

    if (share.requiresApproval && !share.approved) {
      throw new Error('Share requires approval');
    }

    // Decrypt shared data
    const privateKey = await this.getCurrentUserPrivateKey();
    const decryptedData = await this.decryptFromSender(share.encryptedData, privateKey);

    // Create local credential from shared data
    const newCredential = await passwordManager.saveCredential({
      domain: decryptedData.domain,
      username: decryptedData.username,
      password: decryptedData.password,
      notes: `Shared by ${share.sharedBy} on ${new Date(share.createdAt).toLocaleDateString()}\n${decryptedData.notes || ''}`,
      tags: [...(decryptedData.tags || []), 'shared']
    });

    // Update share usage
    share.uses++;
    share.lastUsed = Date.now();

    const updatedShares = shares.map(s => s.id === shareId ? share : s);
    await chrome.storage.local.set({ passwordShares: updatedShares });

    // Add to audit log
    await this.addAuditEntry({
      action: 'share_accepted',
      shareId: shareId,
      credentialId: newCredential,
      sharedBy: share.sharedBy
    });

    return {
      credentialId: newCredential,
      sharedBy: share.sharedBy,
      permissions: share.permissions
    };
  }

  // Revoke a share
  async revokeShare(shareId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    const shares = await this.getShares();
    const share = shares.find(s => s.id === shareId);

    if (!share) {
      throw new Error('Share not found');
    }

    // Remove share
    const updatedShares = shares.filter(s => s.id !== shareId);
    await chrome.storage.local.set({ passwordShares: updatedShares });

    // Add to audit log
    await this.addAuditEntry({
      action: 'share_revoked',
      shareId: shareId,
      credentialId: share.credentialId,
      recipient: share.sharedWith,
      reason: 'Manual revocation'
    });

    // Notify recipient
    await this.notifyRevocation(share);

    return { success: true };
  }

  // Update share permissions
  async updateSharePermissions(shareId, newPermissions) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    const shares = await this.getShares();
    const share = shares.find(s => s.id === shareId);

    if (!share) {
      throw new Error('Share not found');
    }

    const oldPermissions = share.permissions;
    share.permissions = newPermissions;
    share.modifiedAt = Date.now();

    const updatedShares = shares.map(s => s.id === shareId ? share : s);
    await chrome.storage.local.set({ passwordShares: updatedShares });

    // Add to audit log
    await this.addAuditEntry({
      action: 'share_updated',
      shareId: shareId,
      credentialId: share.credentialId,
      changes: {
        permissions: { old: oldPermissions, new: newPermissions }
      }
    });

    return { success: true };
  }

  // Approve a pending share
  async approveShare(shareId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    const shares = await this.getShares();
    const share = shares.find(s => s.id === shareId);

    if (!share) {
      throw new Error('Share not found');
    }

    if (!share.requiresApproval) {
      throw new Error('Share does not require approval');
    }

    share.approved = true;
    share.approvedAt = Date.now();

    const updatedShares = shares.map(s => s.id === shareId ? share : s);
    await chrome.storage.local.set({ passwordShares: updatedShares });

    // Notify recipient
    await this.notifyApproval(share);

    return { success: true };
  }

  // Get all shares (sent and received)
  async getShares() {
    const data = await chrome.storage.local.get('passwordShares');
    return data.passwordShares || [];
  }

  // Get shares for a specific credential
  async getCredentialShares(credentialId) {
    const shares = await this.getShares();
    const currentUser = await this.getCurrentUserEmail();

    return shares.filter(s => 
      s.credentialId === credentialId && 
      s.sharedBy === currentUser &&
      s.expiresAt > Date.now()
    );
  }

  // Get received shares
  async getReceivedShares() {
    const shares = await this.getShares();
    const currentUser = await this.getCurrentUserEmail();

    return shares.filter(s => 
      s.sharedWith === currentUser &&
      s.expiresAt > Date.now()
    );
  }

  // Encrypt data for recipient
  async encryptForRecipient(data, recipientPublicKey) {
    // Generate ephemeral key for this share
    const ephemeralKey = crypto.getRandomValues(new Uint8Array(32));

    // Encrypt data with ephemeral key
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
      'raw',
      ephemeralKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(data))
    );

    // Encrypt ephemeral key with recipient's public key
    const publicKey = await crypto.subtle.importKey(
      'spki',
      recipientPublicKey,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['encrypt']
    );

    const encryptedKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      ephemeralKey
    );

    return {
      encryptedData: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
      encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
      iv: Array.from(iv)
    };
  }

  // Decrypt data from sender
  async decryptFromSender(encryptedShare, privateKey) {
    // Decrypt ephemeral key
    const importedPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKey,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['decrypt']
    );

    const ephemeralKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      importedPrivateKey,
      Uint8Array.from(atob(encryptedShare.encryptedKey), c => c.charCodeAt(0))
    );

    // Decrypt data with ephemeral key
    const key = await crypto.subtle.importKey(
      'raw',
      ephemeralKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encryptedShare.iv) },
      key,
      Uint8Array.from(atob(encryptedShare.encryptedData), c => c.charCodeAt(0))
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  // Get recipient's public key (mock - would query key server)
  async getRecipientPublicKey(email) {
    // Check cache
    if (this.publicKeyCache.has(email)) {
      return this.publicKeyCache.get(email);
    }

    // In production, query key server
    // For now, generate mock key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    this.publicKeyCache.set(email, publicKey);

    return publicKey;
  }

  // Get current user's private key
  async getCurrentUserPrivateKey() {
    // In production, retrieve from secure storage
    // For now, return mock key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    return crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  }

  // Get current user email
  async getCurrentUserEmail() {
    // In production, get from auth system
    return 'user@example.com';
  }

  // Generate share URL
  async generateShareUrl(shareId) {
    const baseUrl = 'https://passwords.browseros.com/share/';
    const token = btoa(shareId).replace(/=/g, '');
    return `${baseUrl}${token}`;
  }

  // Add audit log entry
  async addAuditEntry(entry) {
    const auditLog = await chrome.storage.local.get('shareAuditLog');
    const log = auditLog.shareAuditLog || [];

    log.push({
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      user: await this.getCurrentUserEmail(),
      ...entry
    });

    // Keep last 1000 entries
    if (log.length > 1000) {
      log.splice(0, log.length - 1000);
    }

    await chrome.storage.local.set({ shareAuditLog: log });
  }

  // Get audit log
  async getAuditLog(filters = {}) {
    const auditLog = await chrome.storage.local.get('shareAuditLog');
    let log = auditLog.shareAuditLog || [];

    // Apply filters
    if (filters.credentialId) {
      log = log.filter(e => e.credentialId === filters.credentialId);
    }

    if (filters.shareId) {
      log = log.filter(e => e.shareId === filters.shareId);
    }

    if (filters.action) {
      log = log.filter(e => e.action === filters.action);
    }

    if (filters.startDate) {
      log = log.filter(e => e.timestamp >= filters.startDate);
    }

    if (filters.endDate) {
      log = log.filter(e => e.timestamp <= filters.endDate);
    }

    return log.sort((a, b) => b.timestamp - a.timestamp);
  }

  // Clean expired shares
  async cleanExpiredShares() {
    const shares = await this.getShares();
    const now = Date.now();
    const activeShares = shares.filter(s => s.expiresAt > now);

    if (activeShares.length !== shares.length) {
      await chrome.storage.local.set({ passwordShares: activeShares });
      
      // Log cleanup
      await this.addAuditEntry({
        action: 'cleanup',
        removed: shares.length - activeShares.length
      });
    }
  }

  // Notification methods (mock implementations)
  async notifyRecipient(share, domain) {
    console.log(`Notifying ${share.sharedWith} about shared credential for ${domain}`);
  }

  async notifyRevocation(share) {
    console.log(`Notifying ${share.sharedWith} about revoked share`);
  }

  async notifyApproval(share) {
    console.log(`Notifying ${share.sharedWith} about approved share`);
  }

  // Get sharing statistics
  async getSharingStats() {
    const shares = await this.getShares();
    const currentUser = await this.getCurrentUserEmail();
    const now = Date.now();

    return {
      totalShares: shares.length,
      activeShares: shares.filter(s => s.expiresAt > now).length,
      sentShares: shares.filter(s => s.sharedBy === currentUser).length,
      receivedShares: shares.filter(s => s.sharedWith === currentUser).length,
      pendingApprovals: shares.filter(s => s.requiresApproval && !s.approved).length,
      expiringToday: shares.filter(s => 
        s.expiresAt > now && 
        s.expiresAt < now + 24 * 60 * 60 * 1000
      ).length
    };
  }
}

// Export singleton instance
const passwordSharingManager = new PasswordSharingManager();

// Schedule periodic cleanup
setInterval(() => {
  passwordSharingManager.cleanExpiredShares();
}, 60 * 60 * 1000); // Every hour

export default passwordSharingManager;