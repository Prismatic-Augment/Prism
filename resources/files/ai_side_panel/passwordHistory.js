// Password History Module - Track and manage password changes

import passwordManager from './passwordManager.js';

class PasswordHistoryManager {
  constructor() {
    this.maxHistoryPerCredential = 10;
    this.retentionDays = 90;
  }

  // Add password to history
  async addToHistory(credentialId, oldPassword, metadata = {}) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const historyKey = `history_${credentialId}`;
    let existingHistory = await this.getHistory(credentialId);
    
    const historyEntry = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      passwordHash: await this.hashPassword(oldPassword),
      encryptedPassword: await passwordManager.encrypt(oldPassword),
      metadata: {
        ...metadata,
        changedFrom: metadata.source || 'manual',
        userAgent: navigator.userAgent,
        ipAddress: metadata.ipAddress || 'local'
      }
    };

    // Add to beginning of array
    existingHistory.unshift(historyEntry);

    // Trim history to max length
    if (existingHistory.length > this.maxHistoryPerCredential) {
      existingHistory = existingHistory.slice(0, this.maxHistoryPerCredential);
    }

    // Clean old entries
    const cutoffTime = Date.now() - (this.retentionDays * 24 * 60 * 60 * 1000);
    existingHistory = existingHistory.filter(entry => entry.timestamp > cutoffTime);

    await chrome.storage.local.set({ [historyKey]: existingHistory });
    return historyEntry.id;
  }

  // Get password history for a credential
  async getHistory(credentialId) {
    const historyKey = `history_${credentialId}`;
    const data = await chrome.storage.local.get(historyKey);
    return data[historyKey] || [];
  }

  // Restore a previous password
  async restorePassword(credentialId, historyId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const history = await this.getHistory(credentialId);
    const historyEntry = history.find(h => h.id === historyId);

    if (!historyEntry) {
      throw new Error('History entry not found');
    }

    // Decrypt the historical password
    const oldPassword = await passwordManager.decrypt(historyEntry.encryptedPassword);

    // Get current credential
    const credentials = await passwordManager.getAllCredentials();
    const credential = credentials.find(c => c.id === credentialId);

    if (!credential) {
      throw new Error('Credential not found');
    }

    // Decrypt current password to add to history
    const currentDecrypted = await passwordManager.decrypt(credential.encrypted);

    // Add current password to history before restoring
    await this.addToHistory(credentialId, currentDecrypted.password, {
      source: 'restore',
      restoredFrom: historyId
    });

    // Update credential with historical password
    currentDecrypted.password = oldPassword;
    credential.encrypted = await passwordManager.encrypt(currentDecrypted);
    credential.lastModified = Date.now();

    // Save updated credential
    const updatedCredentials = credentials.map(c => 
      c.id === credentialId ? credential : c
    );
    await chrome.storage.local.set({ credentials: updatedCredentials });

    return {
      success: true,
      restoredFrom: new Date(historyEntry.timestamp)
    };
  }

  // Check if password was used before
  async checkPasswordReuse(credentialId, newPassword) {
    const history = await this.getHistory(credentialId);
    const newHash = await this.hashPassword(newPassword);

    for (const entry of history) {
      if (entry.passwordHash === newHash) {
        return {
          reused: true,
          lastUsed: new Date(entry.timestamp),
          daysAgo: Math.floor((Date.now() - entry.timestamp) / (1000 * 60 * 60 * 24))
        };
      }
    }

    return { reused: false };
  }

  // Get password change frequency
  async getChangeFrequency(credentialId) {
    const history = await this.getHistory(credentialId);
    
    if (history.length < 2) {
      return {
        averageDays: null,
        changes: history.length,
        lastChange: history[0]?.timestamp || null
      };
    }

    const changes = [];
    for (let i = 0; i < history.length - 1; i++) {
      changes.push(history[i].timestamp - history[i + 1].timestamp);
    }

    const averageMs = changes.reduce((a, b) => a + b, 0) / changes.length;
    const averageDays = Math.floor(averageMs / (1000 * 60 * 60 * 24));

    return {
      averageDays,
      changes: history.length,
      lastChange: history[0].timestamp,
      trend: this.analyzeTrend(changes)
    };
  }

  // Analyze password change trend
  analyzeTrend(changes) {
    if (changes.length < 3) return 'insufficient_data';

    const recent = changes.slice(0, Math.floor(changes.length / 2));
    const older = changes.slice(Math.floor(changes.length / 2));

    const recentAvg = recent.reduce((a, b) => a + b, 0) / recent.length;
    const olderAvg = older.reduce((a, b) => a + b, 0) / older.length;

    if (recentAvg < olderAvg * 0.8) return 'improving';
    if (recentAvg > olderAvg * 1.2) return 'declining';
    return 'stable';
  }

  // Generate password history report
  async generateHistoryReport(credentialId) {
    const history = await this.getHistory(credentialId);
    const frequency = await this.getChangeFrequency(credentialId);

    const report = {
      credentialId,
      totalChanges: history.length,
      frequency,
      timeline: history.map(h => ({
        date: new Date(h.timestamp),
        source: h.metadata.changedFrom,
        daysAgo: Math.floor((Date.now() - h.timestamp) / (1000 * 60 * 60 * 24))
      })),
      patterns: await this.analyzePatterns(history)
    };

    return report;
  }

  // Analyze password patterns
  async analyzePatterns(history) {
    const patterns = {
      regularRotation: false,
      reuseDetected: false,
      strengthTrend: 'unknown',
      commonChangeTimes: []
    };

    if (history.length < 3) return patterns;

    // Check for regular rotation
    const intervals = [];
    for (let i = 0; i < history.length - 1; i++) {
      intervals.push(history[i].timestamp - history[i + 1].timestamp);
    }

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, interval) => 
      sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
    
    // Low variance indicates regular rotation
    patterns.regularRotation = variance < Math.pow(avgInterval * 0.2, 2);

    // Check common change times (day of week, time of day)
    const changeDays = history.map(h => new Date(h.timestamp).getDay());
    const changeHours = history.map(h => new Date(h.timestamp).getHours());

    patterns.commonChangeTimes = {
      preferredDay: this.findMode(changeDays),
      preferredHour: this.findMode(changeHours)
    };

    return patterns;
  }

  // Find most common value in array
  findMode(arr) {
    const frequency = {};
    let maxFreq = 0;
    let mode = null;

    for (const val of arr) {
      frequency[val] = (frequency[val] || 0) + 1;
      if (frequency[val] > maxFreq) {
        maxFreq = frequency[val];
        mode = val;
      }
    }

    return mode;
  }

  // Hash password for comparison
  async hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }

  // Clean old history entries across all credentials
  async cleanOldHistory() {
    const cutoffTime = Date.now() - (this.retentionDays * 24 * 60 * 60 * 1000);
    const allKeys = await chrome.storage.local.get(null);
    
    const historyKeys = Object.keys(allKeys).filter(key => key.startsWith('history_'));
    
    for (const key of historyKeys) {
      const history = allKeys[key];
      const cleaned = history.filter(entry => entry.timestamp > cutoffTime);
      
      if (cleaned.length !== history.length) {
        await chrome.storage.local.set({ [key]: cleaned });
      }
    }
  }

  // Export history for a credential
  async exportHistory(credentialId, format = 'json') {
    const history = await this.getHistory(credentialId);
    const report = await this.generateHistoryReport(credentialId);

    if (format === 'json') {
      return JSON.stringify({ history, report }, null, 2);
    } else if (format === 'csv') {
      const rows = [
        ['Password History Report'],
        [`Credential ID: ${credentialId}`],
        [`Generated: ${new Date().toISOString()}`],
        [''],
        ['Date', 'Days Ago', 'Source', 'User Agent']
      ];

      for (const entry of history) {
        rows.push([
          new Date(entry.timestamp).toISOString(),
          Math.floor((Date.now() - entry.timestamp) / (1000 * 60 * 60 * 24)),
          entry.metadata.changedFrom,
          entry.metadata.userAgent.split(' ').pop() // Browser info only
        ]);
      }

      return rows.map(row => row.join(',')).join('\n');
    }
  }
}

// Export singleton instance
const passwordHistoryManager = new PasswordHistoryManager();
export default passwordHistoryManager;