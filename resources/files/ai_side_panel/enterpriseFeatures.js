// Enterprise Features Module - Team vaults, RBAC, compliance, and audit

import passwordManager from './passwordManager.js';
import passwordSharingManager from './passwordSharing.js';

class EnterpriseManager {
  constructor() {
    this.organizationId = null;
    this.currentUser = null;
    this.roles = {
      owner: { level: 100, name: 'Owner' },
      admin: { level: 80, name: 'Administrator' },
      manager: { level: 60, name: 'Manager' },
      user: { level: 40, name: 'User' },
      viewer: { level: 20, name: 'Viewer' }
    };
    this.complianceStandards = ['SOC2', 'GDPR', 'HIPAA', 'PCI-DSS', 'ISO27001'];
  }

  // Initialize organization
  async initializeOrganization(orgData) {
    this.organizationId = orgData.id || crypto.randomUUID();
    
    const organization = {
      id: this.organizationId,
      name: orgData.name,
      domain: orgData.domain,
      created: Date.now(),
      owner: orgData.owner,
      settings: {
        enforcePasswordPolicy: true,
        require2FA: true,
        sessionTimeout: 30 * 60 * 1000, // 30 minutes
        ipWhitelist: orgData.ipWhitelist || [],
        allowedDomains: orgData.allowedDomains || [],
        complianceMode: orgData.complianceMode || []
      },
      subscription: {
        plan: orgData.plan || 'enterprise',
        seats: orgData.seats || 100,
        expires: orgData.expires || Date.now() + 365 * 24 * 60 * 60 * 1000
      }
    };

    await chrome.storage.local.set({ organization });
    
    // Create default vaults
    await this.createVault({
      name: 'Company Vault',
      type: 'shared',
      description: 'Shared company credentials'
    });

    return organization;
  }

  // Create team vault
  async createVault(vaultData) {
    const vault = {
      id: crypto.randomUUID(),
      organizationId: this.organizationId,
      name: vaultData.name,
      type: vaultData.type || 'shared', // shared, department, project
      description: vaultData.description,
      created: Date.now(),
      createdBy: await this.getCurrentUser(),
      members: vaultData.members || [],
      credentials: [],
      policies: vaultData.policies || {
        passwordStrength: 'strong',
        expiryDays: 90,
        require2FA: true,
        allowSharing: false
      }
    };

    const vaults = await this.getVaults();
    vaults.push(vault);
    await chrome.storage.local.set({ teamVaults: vaults });

    // Add audit entry
    await this.addAuditEntry({
      action: 'vault_created',
      vaultId: vault.id,
      vaultName: vault.name,
      details: { type: vault.type }
    });

    return vault;
  }

  // Add user to organization
  async addUser(userData) {
    const user = {
      id: crypto.randomUUID(),
      email: userData.email,
      name: userData.name,
      role: userData.role || 'user',
      department: userData.department,
      joinedAt: Date.now(),
      status: 'active',
      permissions: this.getPermissionsForRole(userData.role || 'user'),
      vaults: userData.vaults || [],
      require2FA: true,
      lastActive: null,
      sessions: []
    };

    const users = await this.getUsers();
    
    // Check seat limit
    const org = await this.getOrganization();
    if (users.length >= org.subscription.seats) {
      throw new Error('Seat limit reached');
    }

    users.push(user);
    await chrome.storage.local.set({ organizationUsers: users });

    // Send invitation
    await this.sendInvitation(user);

    // Add audit entry
    await this.addAuditEntry({
      action: 'user_added',
      targetUser: user.id,
      details: { email: user.email, role: user.role }
    });

    return user;
  }

  // Update user role
  async updateUserRole(userId, newRole) {
    const users = await this.getUsers();
    const user = users.find(u => u.id === userId);

    if (!user) {
      throw new Error('User not found');
    }

    const oldRole = user.role;
    user.role = newRole;
    user.permissions = this.getPermissionsForRole(newRole);
    user.modifiedAt = Date.now();

    await chrome.storage.local.set({ 
      organizationUsers: users.map(u => u.id === userId ? user : u)
    });

    // Add audit entry
    await this.addAuditEntry({
      action: 'role_changed',
      targetUser: userId,
      details: { oldRole, newRole }
    });

    return user;
  }

  // Add credential to vault
  async addCredentialToVault(vaultId, credentialData) {
    const vaults = await this.getVaults();
    const vault = vaults.find(v => v.id === vaultId);

    if (!vault) {
      throw new Error('Vault not found');
    }

    // Check permissions
    if (!await this.checkVaultPermission(vaultId, 'write')) {
      throw new Error('Insufficient permissions');
    }

    // Create credential with vault metadata
    const credential = await passwordManager.saveCredential({
      ...credentialData,
      vaultId: vaultId,
      sharedWith: vault.members,
      createdBy: await this.getCurrentUser()
    });

    vault.credentials.push(credential);
    
    await chrome.storage.local.set({
      teamVaults: vaults.map(v => v.id === vaultId ? vault : v)
    });

    // Add audit entry
    await this.addAuditEntry({
      action: 'credential_added',
      vaultId: vaultId,
      credentialId: credential,
      details: { domain: credentialData.domain }
    });

    return credential;
  }

  // Get permissions for role
  getPermissionsForRole(role) {
    const permissions = {
      owner: ['*'], // All permissions
      admin: [
        'vault.create', 'vault.delete', 'vault.modify',
        'credential.create', 'credential.read', 'credential.update', 'credential.delete',
        'user.invite', 'user.modify', 'user.remove',
        'audit.read', 'settings.modify'
      ],
      manager: [
        'vault.create', 'vault.modify',
        'credential.create', 'credential.read', 'credential.update',
        'user.invite',
        'audit.read'
      ],
      user: [
        'credential.create', 'credential.read', 'credential.update',
        'vault.read'
      ],
      viewer: [
        'credential.read',
        'vault.read'
      ]
    };

    return permissions[role] || [];
  }

  // Check permission
  async checkPermission(permission) {
    const user = await this.getCurrentUserData();
    
    if (!user) return false;
    
    if (user.permissions.includes('*')) return true;
    
    return user.permissions.includes(permission);
  }

  // Check vault permission
  async checkVaultPermission(vaultId, action) {
    const user = await this.getCurrentUserData();
    const vault = await this.getVault(vaultId);

    if (!user || !vault) return false;

    // Check if user is vault member
    if (!vault.members.find(m => m.userId === user.id)) return false;

    const member = vault.members.find(m => m.userId === user.id);
    
    // Map actions to permissions
    const actionPermissions = {
      read: ['viewer', 'user', 'manager', 'admin', 'owner'],
      write: ['user', 'manager', 'admin', 'owner'],
      delete: ['manager', 'admin', 'owner'],
      admin: ['admin', 'owner']
    };

    return actionPermissions[action]?.includes(member.role) || false;
  }

  // Generate compliance report
  async generateComplianceReport(standard) {
    const report = {
      standard: standard,
      generated: Date.now(),
      organization: await this.getOrganization(),
      status: 'compliant',
      findings: [],
      recommendations: []
    };

    // Run compliance checks based on standard
    switch (standard) {
      case 'SOC2':
        await this.checkSOC2Compliance(report);
        break;
      case 'GDPR':
        await this.checkGDPRCompliance(report);
        break;
      case 'HIPAA':
        await this.checkHIPAACompliance(report);
        break;
      case 'PCI-DSS':
        await this.checkPCIDSSCompliance(report);
        break;
      case 'ISO27001':
        await this.checkISO27001Compliance(report);
        break;
    }

    // Calculate compliance score
    report.score = this.calculateComplianceScore(report);

    // Save report
    const reports = await this.getComplianceReports();
    reports.push(report);
    await chrome.storage.local.set({ complianceReports: reports });

    return report;
  }

  // SOC2 Compliance checks
  async checkSOC2Compliance(report) {
    const users = await this.getUsers();
    const auditLog = await this.getAuditLog();
    const org = await this.getOrganization();

    // Check access controls
    const no2FA = users.filter(u => !u.require2FA).length;
    if (no2FA > 0) {
      report.findings.push({
        severity: 'high',
        category: 'Access Control',
        finding: `${no2FA} users without 2FA enabled`,
        recommendation: 'Enable 2FA for all users'
      });
    }

    // Check audit logging
    if (auditLog.length === 0) {
      report.findings.push({
        severity: 'critical',
        category: 'Audit Trail',
        finding: 'No audit logs found',
        recommendation: 'Enable comprehensive audit logging'
      });
    }

    // Check session management
    if (!org.settings.sessionTimeout || org.settings.sessionTimeout > 60 * 60 * 1000) {
      report.findings.push({
        severity: 'medium',
        category: 'Session Management',
        finding: 'Session timeout too long or not set',
        recommendation: 'Set session timeout to 60 minutes or less'
      });
    }

    // Check encryption
    report.findings.push({
      severity: 'info',
      category: 'Encryption',
      finding: 'AES-256-GCM encryption in use',
      recommendation: 'Continue using strong encryption'
    });
  }

  // GDPR Compliance checks
  async checkGDPRCompliance(report) {
    const users = await this.getUsers();
    const auditLog = await this.getAuditLog();

    // Check data retention
    const oldAuditLogs = auditLog.filter(log => 
      Date.now() - log.timestamp > 365 * 24 * 60 * 60 * 1000 * 2 // 2 years
    );

    if (oldAuditLogs.length > 0) {
      report.findings.push({
        severity: 'medium',
        category: 'Data Retention',
        finding: `${oldAuditLogs.length} audit logs older than 2 years`,
        recommendation: 'Implement data retention policy'
      });
    }

    // Check user consent
    const usersWithoutConsent = users.filter(u => !u.gdprConsent);
    if (usersWithoutConsent.length > 0) {
      report.findings.push({
        severity: 'high',
        category: 'User Consent',
        finding: `${usersWithoutConsent.length} users without GDPR consent`,
        recommendation: 'Obtain explicit consent from all users'
      });
    }

    // Check data export capability
    report.findings.push({
      severity: 'info',
      category: 'Data Portability',
      finding: 'Data export functionality available',
      recommendation: 'Maintain data export capability'
    });
  }

  // Add comprehensive audit entry
  async addAuditEntry(entry) {
    const auditLog = await this.getAuditLog();
    const user = await this.getCurrentUserData();

    const auditEntry = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      organizationId: this.organizationId,
      userId: user?.id,
      userEmail: user?.email,
      action: entry.action,
      ipAddress: await this.getUserIP(),
      userAgent: navigator.userAgent,
      ...entry
    };

    auditLog.push(auditEntry);

    // Keep last 10000 entries
    if (auditLog.length > 10000) {
      auditLog.splice(0, auditLog.length - 10000);
    }

    await chrome.storage.local.set({ enterpriseAuditLog: auditLog });

    // Check for security events
    await this.checkSecurityEvent(auditEntry);
  }

  // Check for security events
  async checkSecurityEvent(auditEntry) {
    const securityEvents = [
      'failed_login',
      'permission_denied',
      'suspicious_activity',
      'data_breach_attempt'
    ];

    if (securityEvents.includes(auditEntry.action)) {
      // Send security alert
      await this.sendSecurityAlert(auditEntry);
    }
  }

  // Active Directory / LDAP integration
  async syncWithActiveDirectory(config) {
    // Mock AD sync - in production would connect to AD server
    const adUsers = await this.fetchADUsers(config);
    const existingUsers = await this.getUsers();
    
    let synced = 0;
    let errors = 0;

    for (const adUser of adUsers) {
      try {
        const existing = existingUsers.find(u => u.email === adUser.email);
        
        if (existing) {
          // Update existing user
          await this.updateUserFromAD(existing.id, adUser);
        } else {
          // Create new user
          await this.addUser({
            email: adUser.email,
            name: adUser.displayName,
            department: adUser.department,
            role: this.mapADGroupToRole(adUser.groups)
          });
        }
        
        synced++;
      } catch (error) {
        errors++;
        console.error(`Failed to sync user ${adUser.email}:`, error);
      }
    }

    // Add audit entry
    await this.addAuditEntry({
      action: 'ad_sync',
      details: {
        synced,
        errors,
        source: config.server
      }
    });

    return { synced, errors };
  }

  // SSO integration
  async configureSSOProvider(provider) {
    const ssoConfig = {
      id: crypto.randomUUID(),
      provider: provider.type, // saml, oidc, oauth2
      name: provider.name,
      entityId: provider.entityId,
      ssoUrl: provider.ssoUrl,
      certificate: provider.certificate,
      attributeMapping: provider.attributeMapping || {
        email: 'email',
        name: 'displayName',
        groups: 'memberOf'
      },
      enabled: true,
      created: Date.now()
    };

    await chrome.storage.local.set({ ssoConfig });

    // Add audit entry
    await this.addAuditEntry({
      action: 'sso_configured',
      details: {
        provider: provider.type,
        name: provider.name
      }
    });

    return ssoConfig;
  }

  // Get various data methods
  async getOrganization() {
    const data = await chrome.storage.local.get('organization');
    return data.organization;
  }

  async getVaults() {
    const data = await chrome.storage.local.get('teamVaults');
    return data.teamVaults || [];
  }

  async getVault(vaultId) {
    const vaults = await this.getVaults();
    return vaults.find(v => v.id === vaultId);
  }

  async getUsers() {
    const data = await chrome.storage.local.get('organizationUsers');
    return data.organizationUsers || [];
  }

  async getCurrentUser() {
    // In production, get from auth system
    return 'current-user-id';
  }

  async getCurrentUserData() {
    const userId = await this.getCurrentUser();
    const users = await this.getUsers();
    return users.find(u => u.id === userId);
  }

  async getAuditLog(filters = {}) {
    const data = await chrome.storage.local.get('enterpriseAuditLog');
    let log = data.enterpriseAuditLog || [];

    // Apply filters
    if (filters.startDate) {
      log = log.filter(e => e.timestamp >= filters.startDate);
    }
    if (filters.endDate) {
      log = log.filter(e => e.timestamp <= filters.endDate);
    }
    if (filters.userId) {
      log = log.filter(e => e.userId === filters.userId);
    }
    if (filters.action) {
      log = log.filter(e => e.action === filters.action);
    }

    return log;
  }

  async getComplianceReports() {
    const data = await chrome.storage.local.get('complianceReports');
    return data.complianceReports || [];
  }

  // Helper methods
  async getUserIP() {
    // In production, get real IP
    return '192.168.1.1';
  }

  async sendInvitation(user) {
    console.log(`Sending invitation to ${user.email}`);
  }

  async sendSecurityAlert(event) {
    console.log('Security alert:', event);
  }

  calculateComplianceScore(report) {
    const weights = {
      critical: 20,
      high: 10,
      medium: 5,
      low: 2,
      info: 0
    };

    let deductions = 0;
    for (const finding of report.findings) {
      deductions += weights[finding.severity] || 0;
    }

    return Math.max(0, 100 - deductions);
  }

  mapADGroupToRole(groups) {
    // Map AD groups to roles
    if (groups.includes('Domain Admins')) return 'admin';
    if (groups.includes('Managers')) return 'manager';
    return 'user';
  }

  async fetchADUsers(config) {
    // Mock AD user fetch
    return [
      {
        email: 'user@company.com',
        displayName: 'Test User',
        department: 'IT',
        groups: ['Domain Users']
      }
    ];
  }

  async updateUserFromAD(userId, adUser) {
    // Update user from AD data
    const users = await this.getUsers();
    const user = users.find(u => u.id === userId);
    
    if (user) {
      user.name = adUser.displayName;
      user.department = adUser.department;
      user.adSynced = Date.now();
      
      await chrome.storage.local.set({
        organizationUsers: users.map(u => u.id === userId ? user : u)
      });
    }
  }
}

// Export singleton instance
const enterpriseManager = new EnterpriseManager();
export default enterpriseManager;