// Emergency Access Module - Grant trusted contacts time-delayed access

import passwordManager from './passwordManager.js';

class EmergencyAccessManager {
  constructor() {
    this.defaultWaitTime = 48; // hours
    this.maxTrustedContacts = 5;
  }

  // Grant emergency access to a contact
  async grantAccess(contactData) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const contacts = await this.getTrustedContacts();
    
    if (contacts.length >= this.maxTrustedContacts) {
      throw new Error(`Maximum ${this.maxTrustedContacts} trusted contacts allowed`);
    }

    const contact = {
      id: crypto.randomUUID(),
      name: contactData.name,
      email: contactData.email,
      waitTime: contactData.waitTime || this.defaultWaitTime,
      grantedAt: Date.now(),
      status: 'active',
      accessLevel: contactData.accessLevel || 'full', // full, readonly, specific
      allowedCredentials: contactData.allowedCredentials || [], // for specific access
      notificationEmail: contactData.notificationEmail || contactData.email,
      verificationCode: this.generateVerificationCode(),
      lastActivity: null,
      accessRequests: []
    };

    contacts.push(contact);
    await chrome.storage.local.set({ emergencyContacts: contacts });

    // Send verification email (mock)
    await this.sendVerificationEmail(contact);

    return contact.id;
  }

  // Request emergency access
  async requestAccess(contactId, verificationCode, reason) {
    const contacts = await this.getTrustedContacts();
    const contact = contacts.find(c => c.id === contactId);

    if (!contact) {
      throw new Error('Contact not found');
    }

    if (contact.verificationCode !== verificationCode) {
      throw new Error('Invalid verification code');
    }

    const request = {
      id: crypto.randomUUID(),
      requestedAt: Date.now(),
      reason: reason || 'Emergency access requested',
      status: 'pending',
      approvalTime: Date.now() + (contact.waitTime * 60 * 60 * 1000),
      ipAddress: 'requesting-ip', // Would get real IP in production
      userAgent: navigator.userAgent
    };

    contact.accessRequests.push(request);
    contact.lastActivity = Date.now();

    // Update contact
    const updatedContacts = contacts.map(c => 
      c.id === contactId ? contact : c
    );
    await chrome.storage.local.set({ emergencyContacts: updatedContacts });

    // Notify account owner
    await this.notifyOwner(contact, request);

    // Schedule access grant
    this.scheduleAccessGrant(contactId, request.id, contact.waitTime);

    return {
      requestId: request.id,
      approvalTime: new Date(request.approvalTime)
    };
  }

  // Cancel access request (by owner)
  async cancelAccessRequest(contactId, requestId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const contacts = await this.getTrustedContacts();
    const contact = contacts.find(c => c.id === contactId);

    if (!contact) {
      throw new Error('Contact not found');
    }

    const request = contact.accessRequests.find(r => r.id === requestId);
    if (!request) {
      throw new Error('Request not found');
    }

    request.status = 'cancelled';
    request.cancelledAt = Date.now();

    // Update contact
    const updatedContacts = contacts.map(c => 
      c.id === contactId ? contact : c
    );
    await chrome.storage.local.set({ emergencyContacts: updatedContacts });

    // Clear any scheduled grants
    this.clearScheduledGrant(requestId);

    return true;
  }

  // Grant immediate access (override wait time)
  async grantImmediateAccess(contactId, requestId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const contacts = await this.getTrustedContacts();
    const contact = contacts.find(c => c.id === contactId);

    if (!contact) {
      throw new Error('Contact not found');
    }

    const request = contact.accessRequests.find(r => r.id === requestId);
    if (!request) {
      throw new Error('Request not found');
    }

    request.status = 'approved';
    request.approvedAt = Date.now();
    request.grantedBy = 'owner';

    // Generate access token
    const accessToken = await this.generateAccessToken(contact, request);

    // Update contact
    const updatedContacts = contacts.map(c => 
      c.id === contactId ? contact : c
    );
    await chrome.storage.local.set({ emergencyContacts: updatedContacts });

    // Send access details to contact
    await this.sendAccessDetails(contact, accessToken);

    return {
      success: true,
      accessToken: accessToken.id
    };
  }

  // Revoke access
  async revokeAccess(contactId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const contacts = await this.getTrustedContacts();
    const contactIndex = contacts.findIndex(c => c.id === contactId);

    if (contactIndex === -1) {
      throw new Error('Contact not found');
    }

    const contact = contacts[contactIndex];
    
    // Revoke all active access tokens
    await this.revokeAllTokens(contactId);

    // Update status
    contact.status = 'revoked';
    contact.revokedAt = Date.now();

    const updatedContacts = [...contacts];
    updatedContacts[contactIndex] = contact;
    
    await chrome.storage.local.set({ emergencyContacts: updatedContacts });

    return true;
  }

  // Remove trusted contact
  async removeContact(contactId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const contacts = await this.getTrustedContacts();
    const filtered = contacts.filter(c => c.id !== contactId);

    if (filtered.length === contacts.length) {
      throw new Error('Contact not found');
    }

    // Revoke any active tokens
    await this.revokeAllTokens(contactId);

    await chrome.storage.local.set({ emergencyContacts: filtered });
    return true;
  }

  // Get all trusted contacts
  async getTrustedContacts() {
    const data = await chrome.storage.local.get('emergencyContacts');
    return data.emergencyContacts || [];
  }

  // Generate verification code
  generateVerificationCode() {
    const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    let code = '';
    for (let i = 0; i < 8; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
      if (i === 3) code += '-';
    }
    return code;
  }

  // Generate access token
  async generateAccessToken(contact, request) {
    const token = {
      id: crypto.randomUUID(),
      contactId: contact.id,
      requestId: request.id,
      createdAt: Date.now(),
      expiresAt: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
      accessLevel: contact.accessLevel,
      allowedCredentials: contact.allowedCredentials,
      used: false
    };

    // Store token
    const tokens = await this.getAccessTokens();
    tokens.push(token);
    await chrome.storage.local.set({ emergencyAccessTokens: tokens });

    return token;
  }

  // Get access tokens
  async getAccessTokens() {
    const data = await chrome.storage.local.get('emergencyAccessTokens');
    return data.emergencyAccessTokens || [];
  }

  // Validate access token
  async validateToken(tokenId) {
    const tokens = await this.getAccessTokens();
    const token = tokens.find(t => t.id === tokenId);

    if (!token) {
      return { valid: false, reason: 'Token not found' };
    }

    if (token.used) {
      return { valid: false, reason: 'Token already used' };
    }

    if (Date.now() > token.expiresAt) {
      return { valid: false, reason: 'Token expired' };
    }

    // Mark as used
    token.used = true;
    token.usedAt = Date.now();

    const updatedTokens = tokens.map(t => 
      t.id === tokenId ? token : t
    );
    await chrome.storage.local.set({ emergencyAccessTokens: updatedTokens });

    return {
      valid: true,
      accessLevel: token.accessLevel,
      allowedCredentials: token.allowedCredentials
    };
  }

  // Revoke all tokens for a contact
  async revokeAllTokens(contactId) {
    const tokens = await this.getAccessTokens();
    const filtered = tokens.filter(t => t.contactId !== contactId);
    await chrome.storage.local.set({ emergencyAccessTokens: filtered });
  }

  // Schedule access grant after wait time
  scheduleAccessGrant(contactId, requestId, waitTimeHours) {
    // In production, this would use a backend service
    // For now, we'll use chrome alarms API
    chrome.alarms.create(`emergency_access_${requestId}`, {
      when: Date.now() + (waitTimeHours * 60 * 60 * 1000)
    });

    // Handle alarm
    chrome.alarms.onAlarm.addListener(async (alarm) => {
      if (alarm.name.startsWith('emergency_access_')) {
        const requestId = alarm.name.split('_')[2];
        await this.processScheduledGrant(contactId, requestId);
      }
    });
  }

  // Clear scheduled grant
  clearScheduledGrant(requestId) {
    chrome.alarms.clear(`emergency_access_${requestId}`);
  }

  // Process scheduled grant
  async processScheduledGrant(contactId, requestId) {
    const contacts = await this.getTrustedContacts();
    const contact = contacts.find(c => c.id === contactId);

    if (!contact) return;

    const request = contact.accessRequests.find(r => r.id === requestId);
    if (!request || request.status !== 'pending') return;

    // Auto-approve after wait time
    request.status = 'approved';
    request.approvedAt = Date.now();
    request.grantedBy = 'auto';

    // Generate access token
    const accessToken = await this.generateAccessToken(contact, request);

    // Update contact
    const updatedContacts = contacts.map(c => 
      c.id === contactId ? contact : c
    );
    await chrome.storage.local.set({ emergencyContacts: updatedContacts });

    // Send access details
    await this.sendAccessDetails(contact, accessToken);
  }

  // Send verification email (mock)
  async sendVerificationEmail(contact) {
    console.log(`Sending verification email to ${contact.email}`);
    console.log(`Verification code: ${contact.verificationCode}`);
    // In production, integrate with email service
  }

  // Notify owner of access request
  async notifyOwner(contact, request) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'assets/icon128.png',
      title: 'Emergency Access Request',
      message: `${contact.name} has requested emergency access. Will be granted in ${contact.waitTime} hours unless cancelled.`,
      priority: 2,
      buttons: [
        { title: 'Cancel' },
        { title: 'Grant Now' }
      ]
    });
  }

  // Send access details to contact
  async sendAccessDetails(contact, token) {
    console.log(`Sending access details to ${contact.email}`);
    console.log(`Access token: ${token.id}`);
    // In production, integrate with secure communication channel
  }

  // Get emergency access status
  async getAccessStatus() {
    const contacts = await this.getTrustedContacts();
    const tokens = await this.getAccessTokens();

    return {
      trustedContacts: contacts.length,
      activeRequests: contacts.reduce((sum, c) => 
        sum + c.accessRequests.filter(r => r.status === 'pending').length, 0
      ),
      activeTokens: tokens.filter(t => !t.used && Date.now() < t.expiresAt).length,
      recentActivity: contacts
        .filter(c => c.lastActivity)
        .sort((a, b) => b.lastActivity - a.lastActivity)
        .slice(0, 5)
        .map(c => ({
          name: c.name,
          activity: new Date(c.lastActivity),
          type: c.accessRequests[c.accessRequests.length - 1]?.status || 'unknown'
        }))
    };
  }
}

// Export singleton instance
const emergencyAccessManager = new EmergencyAccessManager();
export default emergencyAccessManager;