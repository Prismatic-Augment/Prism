// Browser Sync Module - End-to-end encrypted cross-device synchronization

import passwordManager from './passwordManager.js';

class BrowserSyncManager {
  constructor() {
    this.syncEnabled = false;
    this.syncInterval = 5 * 60 * 1000; // 5 minutes
    this.lastSync = null;
    this.syncInProgress = false;
    this.deviceId = this.generateDeviceId();
    this.syncServer = 'wss://sync.browseros-passwords.com'; // Mock server
    this.websocket = null;
    this.conflictResolution = 'newest'; // newest, manual, merge
  }

  // Generate unique device ID
  generateDeviceId() {
    const stored = localStorage.getItem('deviceId');
    if (stored) return stored;

    const id = crypto.randomUUID();
    localStorage.setItem('deviceId', id);
    return id;
  }

  // Enable sync
  async enableSync(syncPassphrase) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    // Derive sync key from passphrase
    const syncKey = await this.deriveSyncKey(syncPassphrase);

    // Generate device key pair for secure communication
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

    // Export public key
    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);

    // Store sync configuration
    const syncConfig = {
      enabled: true,
      syncKey: Array.from(new Uint8Array(syncKey)),
      deviceName: this.getDeviceName(),
      publicKey: Array.from(new Uint8Array(publicKey)),
      privateKey: await crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
      enrolledAt: Date.now(),
      lastSync: null
    };

    await chrome.storage.local.set({ syncConfig });
    this.syncEnabled = true;

    // Connect to sync server
    await this.connectToSyncServer();

    // Perform initial sync
    await this.performSync();

    return {
      success: true,
      deviceId: this.deviceId,
      deviceName: syncConfig.deviceName
    };
  }

  // Disable sync
  async disableSync() {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager must be unlocked');
    }

    // Disconnect from server
    if (this.websocket) {
      this.websocket.close();
    }

    // Remove sync configuration
    await chrome.storage.local.remove('syncConfig');
    this.syncEnabled = false;
    this.lastSync = null;

    // Clear sync metadata
    await this.clearSyncMetadata();

    return { success: true };
  }

  // Connect to sync server
  async connectToSyncServer() {
    return new Promise((resolve, reject) => {
      this.websocket = new WebSocket(this.syncServer);

      this.websocket.onopen = async () => {
        console.log('Connected to sync server');
        
        // Authenticate device
        await this.authenticateDevice();
        
        // Start heartbeat
        this.startHeartbeat();
        
        resolve();
      };

      this.websocket.onmessage = async (event) => {
        await this.handleSyncMessage(JSON.parse(event.data));
      };

      this.websocket.onerror = (error) => {
        console.error('Sync server error:', error);
        reject(error);
      };

      this.websocket.onclose = () => {
        console.log('Disconnected from sync server');
        this.stopHeartbeat();
        
        // Attempt reconnection
        if (this.syncEnabled) {
          setTimeout(() => this.connectToSyncServer(), 5000);
        }
      };
    });
  }

  // Authenticate device with sync server
  async authenticateDevice() {
    const config = await chrome.storage.local.get('syncConfig');
    const syncConfig = config.syncConfig;

    const authMessage = {
      type: 'auth',
      deviceId: this.deviceId,
      deviceName: syncConfig.deviceName,
      publicKey: syncConfig.publicKey,
      timestamp: Date.now()
    };

    // Sign message
    const signature = await this.signMessage(authMessage);
    authMessage.signature = signature;

    this.websocket.send(JSON.stringify(authMessage));
  }

  // Perform sync
  async performSync() {
    if (!this.syncEnabled || this.syncInProgress) return;

    this.syncInProgress = true;

    try {
      // Get local data
      const localData = await this.getLocalSyncData();

      // Get remote data
      const remoteData = await this.getRemoteSyncData();

      // Merge data
      const mergedData = await this.mergeData(localData, remoteData);

      // Apply changes locally
      await this.applyChanges(mergedData.local);

      // Send changes to server
      await this.sendChanges(mergedData.remote);

      // Update sync timestamp
      this.lastSync = Date.now();
      await this.updateSyncMetadata();

      return {
        success: true,
        itemsSynced: mergedData.changeCount,
        conflicts: mergedData.conflicts
      };

    } catch (error) {
      console.error('Sync error:', error);
      throw error;
    } finally {
      this.syncInProgress = false;
    }
  }

  // Get local data for sync
  async getLocalSyncData() {
    const credentials = await passwordManager.getAllCredentials();
    const notes = await chrome.storage.local.get('secureNotes');
    const syncMeta = await chrome.storage.local.get('syncMetadata');

    return {
      credentials: credentials.map(c => ({
        ...c,
        syncMeta: syncMeta.syncMetadata?.[c.id] || {}
      })),
      notes: notes.secureNotes || [],
      deviceId: this.deviceId,
      timestamp: Date.now()
    };
  }

  // Get remote sync data
  async getRemoteSyncData() {
    return new Promise((resolve, reject) => {
      const request = {
        type: 'sync_pull',
        deviceId: this.deviceId,
        lastSync: this.lastSync || 0
      };

      this.websocket.send(JSON.stringify(request));

      // Wait for response
      const handler = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === 'sync_data') {
          this.websocket.removeEventListener('message', handler);
          resolve(message.data);
        }
      };

      this.websocket.addEventListener('message', handler);

      // Timeout after 30 seconds
      setTimeout(() => {
        this.websocket.removeEventListener('message', handler);
        reject(new Error('Sync timeout'));
      }, 30000);
    });
  }

  // Merge local and remote data
  async mergeData(local, remote) {
    const merged = {
      local: [],  // Changes to apply locally
      remote: [], // Changes to send to server
      conflicts: [],
      changeCount: 0
    };

    // Merge credentials
    const credentialMap = new Map();

    // Add local credentials to map
    local.credentials.forEach(cred => {
      credentialMap.set(cred.id, { local: cred });
    });

    // Add remote credentials to map
    remote.credentials?.forEach(cred => {
      if (credentialMap.has(cred.id)) {
        credentialMap.get(cred.id).remote = cred;
      } else {
        credentialMap.set(cred.id, { remote: cred });
      }
    });

    // Process each credential
    for (const [id, data] of credentialMap) {
      const result = await this.resolveConflict(data.local, data.remote);

      if (result.conflict) {
        merged.conflicts.push(result);
      }

      if (result.updateLocal) {
        merged.local.push(result.updateLocal);
        merged.changeCount++;
      }

      if (result.updateRemote) {
        merged.remote.push(result.updateRemote);
        merged.changeCount++;
      }
    }

    return merged;
  }

  // Resolve conflicts between local and remote data
  async resolveConflict(local, remote) {
    if (!local) {
      // New remote item
      return {
        updateLocal: remote,
        conflict: false
      };
    }

    if (!remote) {
      // New local item
      return {
        updateRemote: local,
        conflict: false
      };
    }

    // Compare timestamps
    const localTime = local.lastModified || 0;
    const remoteTime = remote.lastModified || 0;

    if (localTime === remoteTime) {
      // No changes
      return { conflict: false };
    }

    // Check for conflicts
    if (local.syncMeta?.version !== remote.syncMeta?.version) {
      // Conflict detected
      switch (this.conflictResolution) {
        case 'newest':
          if (localTime > remoteTime) {
            return {
              updateRemote: local,
              conflict: false
            };
          } else {
            return {
              updateLocal: remote,
              conflict: false
            };
          }

        case 'manual':
          return {
            conflict: true,
            local,
            remote,
            resolve: async (choice) => {
              if (choice === 'local') {
                return { updateRemote: local };
              } else {
                return { updateLocal: remote };
              }
            }
          };

        case 'merge':
          // Attempt to merge changes
          const merged = await this.mergeCredentials(local, remote);
          return {
            updateLocal: merged,
            updateRemote: merged,
            conflict: false
          };
      }
    }

    // No conflict, update older version
    if (localTime > remoteTime) {
      return { updateRemote: local };
    } else {
      return { updateLocal: remote };
    }
  }

  // Merge two versions of a credential
  async mergeCredentials(local, remote) {
    // Decrypt both versions
    const localDecrypted = await passwordManager.decrypt(local.encrypted);
    const remoteDecrypted = await passwordManager.decrypt(remote.encrypted);

    // Merge fields (keep most recent for each field)
    const merged = {
      ...local,
      domain: local.lastModified > remote.lastModified ? local.domain : remote.domain,
      favicon: local.favicon || remote.favicon,
      tags: [...new Set([...(local.tags || []), ...(remote.tags || [])])],
      lastModified: Math.max(local.lastModified, remote.lastModified),
      syncMeta: {
        version: (local.syncMeta?.version || 0) + 1,
        mergedAt: Date.now(),
        devices: [local.syncMeta?.deviceId, remote.syncMeta?.deviceId].filter(Boolean)
      }
    };

    // Merge decrypted data
    const mergedDecrypted = {
      username: localDecrypted.username || remoteDecrypted.username,
      password: local.lastModified > remote.lastModified 
        ? localDecrypted.password 
        : remoteDecrypted.password,
      notes: localDecrypted.notes || remoteDecrypted.notes
    };

    // Re-encrypt
    merged.encrypted = await passwordManager.encrypt(mergedDecrypted);

    return merged;
  }

  // Apply changes locally
  async applyChanges(changes) {
    if (!changes || changes.length === 0) return;

    const credentials = await passwordManager.getAllCredentials();
    const credentialMap = new Map(credentials.map(c => [c.id, c]));

    // Apply each change
    for (const change of changes) {
      credentialMap.set(change.id, change);
    }

    // Save updated credentials
    const updatedCredentials = Array.from(credentialMap.values());
    await chrome.storage.local.set({ credentials: updatedCredentials });
  }

  // Send changes to server
  async sendChanges(changes) {
    if (!changes || changes.length === 0) return;

    const config = await chrome.storage.local.get('syncConfig');
    const syncKey = new Uint8Array(config.syncConfig.syncKey);

    // Encrypt changes for transport
    const encryptedChanges = await this.encryptForTransport(changes, syncKey);

    const message = {
      type: 'sync_push',
      deviceId: this.deviceId,
      changes: encryptedChanges,
      timestamp: Date.now()
    };

    this.websocket.send(JSON.stringify(message));
  }

  // Encrypt data for transport
  async encryptForTransport(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(data))
    );

    return {
      iv: Array.from(iv),
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    };
  }

  // Decrypt data from transport
  async decryptFromTransport(encryptedData, key) {
    const iv = new Uint8Array(encryptedData.iv);
    const data = Uint8Array.from(atob(encryptedData.data), c => c.charCodeAt(0));

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  // Derive sync key from passphrase
  async deriveSyncKey(passphrase) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('browseros-sync-salt'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // Get device name
  getDeviceName() {
    const platform = navigator.platform;
    const browser = navigator.userAgent.match(/(Chrome|Firefox|Safari|Edge)/)?.[1] || 'Browser';
    return `${platform} - ${browser}`;
  }

  // Handle sync messages from server
  async handleSyncMessage(message) {
    switch (message.type) {
      case 'sync_update':
        // New changes available
        await this.performSync();
        break;

      case 'device_added':
        // New device added to account
        this.notifyNewDevice(message.device);
        break;

      case 'conflict':
        // Handle sync conflict
        await this.handleSyncConflict(message.conflict);
        break;

      case 'error':
        console.error('Sync server error:', message.error);
        break;
    }
  }

  // Start heartbeat to keep connection alive
  startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      if (this.websocket?.readyState === WebSocket.OPEN) {
        this.websocket.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000);
  }

  // Stop heartbeat
  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
  }

  // Sign message for authentication
  async signMessage(message) {
    const config = await chrome.storage.local.get('syncConfig');
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      config.syncConfig.privateKey,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateKey,
      new TextEncoder().encode(JSON.stringify(message))
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }

  // Update sync metadata
  async updateSyncMetadata() {
    const metadata = await chrome.storage.local.get('syncMetadata');
    const syncMetadata = metadata.syncMetadata || {};

    syncMetadata.lastSync = this.lastSync;
    syncMetadata.deviceId = this.deviceId;

    await chrome.storage.local.set({ syncMetadata });
  }

  // Clear sync metadata
  async clearSyncMetadata() {
    await chrome.storage.local.remove('syncMetadata');
  }

  // Notify about new device
  notifyNewDevice(device) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'assets/icon128.png',
      title: 'New Device Added',
      message: `${device.name} has been added to your password sync`,
      priority: 1
    });
  }

  // Get sync status
  async getSyncStatus() {
    const config = await chrome.storage.local.get('syncConfig');
    
    return {
      enabled: this.syncEnabled,
      connected: this.websocket?.readyState === WebSocket.OPEN,
      lastSync: this.lastSync ? new Date(this.lastSync) : null,
      deviceId: this.deviceId,
      deviceName: config.syncConfig?.deviceName,
      syncInProgress: this.syncInProgress,
      conflictResolution: this.conflictResolution
    };
  }

  // Get connected devices
  async getConnectedDevices() {
    // In production, this would query the sync server
    return [
      {
        id: this.deviceId,
        name: this.getDeviceName(),
        lastSeen: new Date(),
        current: true
      }
    ];
  }

  // Remove device from sync
  async removeDevice(deviceId) {
    if (deviceId === this.deviceId) {
      throw new Error('Cannot remove current device');
    }

    // Send remove request to server
    this.websocket.send(JSON.stringify({
      type: 'remove_device',
      deviceId: deviceId
    }));

    return { success: true };
  }
}

// Export singleton instance
const browserSyncManager = new BrowserSyncManager();
export default browserSyncManager;