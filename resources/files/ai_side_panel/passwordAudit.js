// Password Audit & Security Dashboard Module

import passwordManager from './passwordManager.js';
import aiPasswordAgent from './aiPasswordAgent.js';

class PasswordAuditManager {
  constructor() {
    this.auditCache = new Map();
    this.lastAuditTime = null;
  }

  // Perform comprehensive password audit
  async performFullAudit() {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const startTime = Date.now();
    const credentials = await passwordManager.getAllCredentials();
    const auditResults = {
      summary: {
        totalPasswords: credentials.length,
        uniquePasswords: 0,
        weakPasswords: 0,
        reusedPasswords: 0,
        oldPasswords: 0,
        breachedPasswords: 0,
        securityScore: 100
      },
      details: [],
      recommendations: [],
      timestamp: startTime
    };

    // Track unique passwords
    const passwordHashes = new Map();
    const domainGroups = new Map();

    // Analyze each credential
    for (const cred of credentials) {
      try {
        const decrypted = await passwordManager.decrypt(cred.encrypted);
        const analysis = await this.analyzeCredential(cred, decrypted);
        
        auditResults.details.push(analysis);

        // Track password reuse
        const passwordHash = await this.hashPassword(decrypted.password);
        if (!passwordHashes.has(passwordHash)) {
          passwordHashes.set(passwordHash, []);
        }
        passwordHashes.get(passwordHash).push({
          id: cred.id,
          domain: cred.domain,
          username: decrypted.username
        });

        // Group by domain
        const domain = this.extractDomain(cred.domain);
        if (!domainGroups.has(domain)) {
          domainGroups.set(domain, []);
        }
        domainGroups.get(domain).push(cred.id);

        // Update summary
        if (analysis.strength.score < 60) auditResults.summary.weakPasswords++;
        if (analysis.breached) auditResults.summary.breachedPasswords++;
        if (analysis.age > 90) auditResults.summary.oldPasswords++;

      } catch (error) {
        console.error('Error analyzing credential:', error);
      }
    }

    // Calculate reused passwords
    auditResults.summary.uniquePasswords = passwordHashes.size;
    for (const [hash, uses] of passwordHashes) {
      if (uses.length > 1) {
        auditResults.summary.reusedPasswords += uses.length;
      }
    }

    // Calculate security score
    auditResults.summary.securityScore = this.calculateSecurityScore(auditResults.summary);

    // Generate recommendations
    auditResults.recommendations = this.generateRecommendations(auditResults, passwordHashes, domainGroups);

    // Cache results
    this.auditCache.set('lastAudit', auditResults);
    this.lastAuditTime = startTime;

    // Save audit history
    await this.saveAuditHistory(auditResults);

    return auditResults;
  }

  // Analyze individual credential
  async analyzeCredential(credential, decrypted) {
    const strength = passwordManager.checkPasswordStrength(decrypted.password);
    const breached = await aiPasswordAgent.checkPasswordBreach(decrypted.password);
    const age = Math.floor((Date.now() - credential.lastModified) / (1000 * 60 * 60 * 24)); // Days

    return {
      id: credential.id,
      domain: credential.domain,
      username: decrypted.username,
      strength: strength,
      breached: breached,
      age: age,
      hasTotp: !!credential.totp,
      lastModified: credential.lastModified,
      risks: this.identifyRisks(strength, breached, age)
    };
  }

  // Hash password for reuse detection
  async hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Extract main domain from URL
  extractDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      const parts = hostname.split('.');
      if (parts.length > 2) {
        return parts.slice(-2).join('.');
      }
      return hostname;
    } catch {
      return url;
    }
  }

  // Calculate overall security score
  calculateSecurityScore(summary) {
    let score = 100;
    
    // Deduct for weak passwords (max -30)
    const weakRatio = summary.weakPasswords / summary.totalPasswords;
    score -= Math.min(30, weakRatio * 100);

    // Deduct for reused passwords (max -25)
    const reuseRatio = summary.reusedPasswords / summary.totalPasswords;
    score -= Math.min(25, reuseRatio * 100);

    // Deduct for breached passwords (max -25)
    const breachRatio = summary.breachedPasswords / summary.totalPasswords;
    score -= Math.min(25, breachRatio * 100);

    // Deduct for old passwords (max -20)
    const oldRatio = summary.oldPasswords / summary.totalPasswords;
    score -= Math.min(20, oldRatio * 50);

    return Math.max(0, Math.round(score));
  }

  // Identify risks for a credential
  identifyRisks(strength, breached, age) {
    const risks = [];

    if (breached) {
      risks.push({
        type: 'critical',
        message: 'Password found in data breach',
        action: 'Change immediately'
      });
    }

    if (strength.score < 40) {
      risks.push({
        type: 'high',
        message: 'Very weak password',
        action: 'Generate strong password'
      });
    } else if (strength.score < 60) {
      risks.push({
        type: 'medium',
        message: 'Weak password',
        action: 'Strengthen password'
      });
    }

    if (age > 180) {
      risks.push({
        type: 'medium',
        message: `Password is ${age} days old`,
        action: 'Consider updating'
      });
    }

    return risks;
  }

  // Generate actionable recommendations
  generateRecommendations(auditResults, passwordHashes, domainGroups) {
    const recommendations = [];

    // Critical: Breached passwords
    if (auditResults.summary.breachedPasswords > 0) {
      recommendations.push({
        priority: 'critical',
        title: 'Breached Passwords Detected',
        description: `${auditResults.summary.breachedPasswords} password(s) have been found in data breaches`,
        action: 'Change these passwords immediately',
        affectedCount: auditResults.summary.breachedPasswords
      });
    }

    // High: Password reuse
    const reusedGroups = Array.from(passwordHashes.values()).filter(group => group.length > 1);
    if (reusedGroups.length > 0) {
      recommendations.push({
        priority: 'high',
        title: 'Password Reuse Detected',
        description: `${reusedGroups.length} passwords are used across multiple accounts`,
        action: 'Generate unique passwords for each account',
        affectedCount: auditResults.summary.reusedPasswords,
        details: reusedGroups.map(group => ({
          accounts: group.map(g => `${g.username} (${this.extractDomain(g.domain)})`)
        }))
      });
    }

    // Medium: Weak passwords
    if (auditResults.summary.weakPasswords > 0) {
      recommendations.push({
        priority: 'medium',
        title: 'Weak Passwords',
        description: `${auditResults.summary.weakPasswords} password(s) don't meet security standards`,
        action: 'Strengthen these passwords',
        affectedCount: auditResults.summary.weakPasswords
      });
    }

    // Low: Old passwords
    if (auditResults.summary.oldPasswords > 0) {
      recommendations.push({
        priority: 'low',
        title: 'Aging Passwords',
        description: `${auditResults.summary.oldPasswords} password(s) are over 90 days old`,
        action: 'Consider rotating old passwords',
        affectedCount: auditResults.summary.oldPasswords
      });
    }

    // Info: Enable 2FA
    const no2FA = auditResults.details.filter(d => !d.hasTotp && d.risks.length > 0);
    if (no2FA.length > 0) {
      recommendations.push({
        priority: 'info',
        title: 'Enable Two-Factor Authentication',
        description: `${no2FA.length} high-risk account(s) don't have 2FA enabled`,
        action: 'Add 2FA for extra security',
        affectedCount: no2FA.length
      });
    }

    return recommendations;
  }

  // Get password statistics
  async getPasswordStatistics() {
    const credentials = await passwordManager.getAllCredentials();
    const stats = {
      byStrength: { weak: 0, fair: 0, good: 0, strong: 0 },
      byAge: { week: 0, month: 0, quarter: 0, year: 0, older: 0 },
      byDomain: {},
      withTotp: 0,
      totalCredentials: credentials.length
    };

    for (const cred of credentials) {
      try {
        const decrypted = await passwordManager.decrypt(cred.encrypted);
        const strength = passwordManager.checkPasswordStrength(decrypted.password);
        const age = Date.now() - cred.lastModified;

        // Strength distribution
        stats.byStrength[strength.level]++;

        // Age distribution
        if (age < 7 * 24 * 60 * 60 * 1000) stats.byAge.week++;
        else if (age < 30 * 24 * 60 * 60 * 1000) stats.byAge.month++;
        else if (age < 90 * 24 * 60 * 60 * 1000) stats.byAge.quarter++;
        else if (age < 365 * 24 * 60 * 60 * 1000) stats.byAge.year++;
        else stats.byAge.older++;

        // Domain distribution
        const domain = this.extractDomain(cred.domain);
        stats.byDomain[domain] = (stats.byDomain[domain] || 0) + 1;

        // 2FA status
        if (cred.totp) stats.withTotp++;

      } catch (error) {
        console.error('Error processing credential stats:', error);
      }
    }

    return stats;
  }

  // Save audit history
  async saveAuditHistory(auditResults) {
    const history = await chrome.storage.local.get('auditHistory');
    const auditHistory = history.auditHistory || [];
    
    // Keep only last 30 audits
    auditHistory.unshift({
      timestamp: auditResults.timestamp,
      score: auditResults.summary.securityScore,
      summary: auditResults.summary
    });
    
    if (auditHistory.length > 30) {
      auditHistory.pop();
    }

    await chrome.storage.local.set({ auditHistory });
  }

  // Get audit history for charts
  async getAuditHistory() {
    const history = await chrome.storage.local.get('auditHistory');
    return history.auditHistory || [];
  }

  // Monitor for security events
  async monitorSecurityEvents() {
    // Check for new breaches periodically
    setInterval(async () => {
      if (passwordManager.isUnlocked && this.lastAuditTime) {
        const timeSinceAudit = Date.now() - this.lastAuditTime;
        if (timeSinceAudit > 24 * 60 * 60 * 1000) { // 24 hours
          // Perform background audit
          const results = await this.performFullAudit();
          
          // Notify if new issues found
          if (results.summary.breachedPasswords > 0) {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'assets/icon128.png',
              title: 'Security Alert',
              message: `${results.summary.breachedPasswords} password(s) found in new data breaches`,
              priority: 2
            });
          }
        }
      }
    }, 60 * 60 * 1000); // Check every hour
  }

  // Export audit report
  async exportAuditReport(format = 'json') {
    const audit = this.auditCache.get('lastAudit');
    if (!audit) {
      throw new Error('No audit data available. Run an audit first.');
    }

    if (format === 'json') {
      return JSON.stringify(audit, null, 2);
    } else if (format === 'csv') {
      return this.generateCSVReport(audit);
    } else if (format === 'pdf') {
      return this.generatePDFReport(audit);
    }
  }

  // Generate CSV report
  generateCSVReport(audit) {
    const rows = [
      ['Password Security Audit Report'],
      [`Generated: ${new Date(audit.timestamp).toLocaleString()}`],
      [''],
      ['Summary'],
      ['Metric', 'Value'],
      ['Total Passwords', audit.summary.totalPasswords],
      ['Unique Passwords', audit.summary.uniquePasswords],
      ['Weak Passwords', audit.summary.weakPasswords],
      ['Reused Passwords', audit.summary.reusedPasswords],
      ['Breached Passwords', audit.summary.breachedPasswords],
      ['Old Passwords (>90 days)', audit.summary.oldPasswords],
      ['Security Score', `${audit.summary.securityScore}/100`],
      [''],
      ['Details'],
      ['Domain', 'Username', 'Strength', 'Breached', 'Age (days)', '2FA', 'Risks']
    ];

    for (const detail of audit.details) {
      rows.push([
        detail.domain,
        detail.username,
        detail.strength.level,
        detail.breached ? 'Yes' : 'No',
        detail.age,
        detail.hasTotp ? 'Yes' : 'No',
        detail.risks.map(r => r.message).join('; ')
      ]);
    }

    return rows.map(row => row.map(cell => 
      typeof cell === 'string' && cell.includes(',') ? `"${cell}"` : cell
    ).join(',')).join('\n');
  }

  // Generate PDF report (placeholder - would need PDF library)
  generatePDFReport(audit) {
    // This would require a PDF generation library
    // For now, return a structured object that could be used with a PDF generator
    return {
      title: 'Password Security Audit Report',
      date: new Date(audit.timestamp).toLocaleString(),
      summary: audit.summary,
      recommendations: audit.recommendations,
      details: audit.details
    };
  }
}

// Export singleton instance
const passwordAuditManager = new PasswordAuditManager();
export default passwordAuditManager;