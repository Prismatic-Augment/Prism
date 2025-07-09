import React, { useState, useEffect, useCallback } from 'react';
import passwordManager from './passwordManager.js';
import aiPasswordAgent from './aiPasswordAgent.js';

// Main Password Manager Component
export const PasswordManagerPanel = () => {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [credentials, setCredentials] = useState([]);
  const [activeView, setActiveView] = useState('list'); // list, add, generate, settings
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Check if password manager is unlocked
  useEffect(() => {
    setIsUnlocked(passwordManager.isUnlocked);
  }, []);

  // Load credentials when unlocked
  useEffect(() => {
    if (isUnlocked) {
      loadCredentials();
    }
  }, [isUnlocked]);

  const loadCredentials = async () => {
    try {
      setLoading(true);
      const allCreds = await passwordManager.getAllCredentials();
      setCredentials(allCreds);
    } catch (err) {
      setError('Failed to load credentials');
    } finally {
      setLoading(false);
    }
  };

  const handleUnlock = async (masterPassword) => {
    try {
      setError('');
      setLoading(true);
      await passwordManager.unlock(masterPassword);
      setIsUnlocked(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!isUnlocked) {
    return <UnlockScreen onUnlock={handleUnlock} error={error} loading={loading} />;
  }

  return (
    <div className="password-manager">
      <Header 
        activeView={activeView} 
        setActiveView={setActiveView}
        onLock={() => {
          passwordManager.lock();
          setIsUnlocked(false);
        }}
      />

      {activeView === 'list' && (
        <CredentialsList 
          credentials={credentials}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          onSelect={setSelectedCredential}
          onReload={loadCredentials}
        />
      )}

      {activeView === 'add' && (
        <AddCredential 
          onSave={async (cred) => {
            await passwordManager.saveCredential(cred);
            await loadCredentials();
            setActiveView('list');
          }}
          onCancel={() => setActiveView('list')}
        />
      )}

      {activeView === 'generate' && (
        <PasswordGenerator />
      )}

      {activeView === 'settings' && (
        <SecuritySettings />
      )}

      {selectedCredential && (
        <CredentialDetails 
          credential={selectedCredential}
          onClose={() => setSelectedCredential(null)}
          onDelete={async (id) => {
            await passwordManager.deleteCredential(id);
            await loadCredentials();
            setSelectedCredential(null);
          }}
        />
      )}
    </div>
  );
};

// Unlock Screen Component
const UnlockScreen = ({ onUnlock, error, loading }) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (password) {
      onUnlock(password);
    }
  };

  return (
    <div className="unlock-screen">
      <div className="unlock-container">
        <div className="lock-icon">🔒</div>
        <h2>Password Manager Locked</h2>
        <p>Enter your master password to unlock</p>
        
        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Master password"
              disabled={loading}
              autoFocus
            />
            <button
              type="button"
              className="toggle-password"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading || !password}>
            {loading ? 'Unlocking...' : 'Unlock'}
          </button>
        </form>

        <div className="unlock-help">
          <p>Forgot your master password?</p>
          <small>Unfortunately, your master password cannot be recovered. You'll need to reset the password manager.</small>
        </div>
      </div>
    </div>
  );
};

// Header Component
const Header = ({ activeView, setActiveView, onLock }) => {
  return (
    <div className="password-header">
      <div className="header-tabs">
        <button 
          className={activeView === 'list' ? 'active' : ''}
          onClick={() => setActiveView('list')}
        >
          🔑 Passwords
        </button>
        <button 
          className={activeView === 'add' ? 'active' : ''}
          onClick={() => setActiveView('add')}
        >
          ➕ Add
        </button>
        <button 
          className={activeView === 'generate' ? 'active' : ''}
          onClick={() => setActiveView('generate')}
        >
          🎲 Generate
        </button>
        <button 
          className={activeView === 'settings' ? 'active' : ''}
          onClick={() => setActiveView('settings')}
        >
          ⚙️ Settings
        </button>
      </div>
      <button className="lock-button" onClick={onLock} title="Lock password manager">
        🔒
      </button>
    </div>
  );
};

// Credentials List Component
const CredentialsList = ({ credentials, searchQuery, setSearchQuery, onSelect, onReload }) => {
  const [autoFillAvailable, setAutoFillAvailable] = useState(false);

  useEffect(() => {
    // Check if we're on a login page
    checkCurrentTab();
  }, []);

  const checkCurrentTab = async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        const forms = await aiPasswordAgent.detectLoginForms(tab.id);
        setAutoFillAvailable(forms.length > 0);
      }
    } catch (err) {
      console.error('Error checking tab:', err);
    }
  };

  const filteredCredentials = credentials.filter(cred => 
    cred.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
    cred.username.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleAutoFill = async (credId) => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        const result = await aiPasswordAgent.autoFillCredentials(tab.id, credId);
        if (result.success) {
          // Show success notification
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'assets/icon128.png',
            title: 'Credentials Filled',
            message: 'Credentials have been auto-filled'
          });
        }
      }
    } catch (err) {
      console.error('Auto-fill error:', err);
    }
  };

  return (
    <div className="credentials-list">
      <div className="search-bar">
        <input
          type="text"
          placeholder="Search passwords..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <button onClick={onReload} title="Refresh">
          🔄
        </button>
      </div>

      {autoFillAvailable && (
        <div className="autofill-notice">
          🔐 Login form detected on this page
        </div>
      )}

      <div className="credentials-items">
        {filteredCredentials.length === 0 ? (
          <div className="empty-state">
            <p>No credentials found</p>
            <small>Add your first password to get started</small>
          </div>
        ) : (
          filteredCredentials.map(cred => (
            <CredentialItem 
              key={cred.id}
              credential={cred}
              onSelect={() => onSelect(cred)}
              onAutoFill={() => handleAutoFill(cred.id)}
              showAutoFill={autoFillAvailable}
            />
          ))
        )}
      </div>
    </div>
  );
};

// Credential Item Component
const CredentialItem = ({ credential, onSelect, onAutoFill, showAutoFill }) => {
  const getDomainIcon = (domain) => {
    try {
      const url = new URL(domain);
      return `https://www.google.com/s2/favicons?domain=${url.hostname}&sz=32`;
    } catch {
      return null;
    }
  };

  return (
    <div className="credential-item" onClick={onSelect}>
      <div className="credential-icon">
        {getDomainIcon(credential.domain) ? (
          <img src={getDomainIcon(credential.domain)} alt="" />
        ) : (
          <span>🌐</span>
        )}
      </div>
      <div className="credential-info">
        <div className="credential-domain">{credential.domain}</div>
        <div className="credential-username">{credential.username}</div>
      </div>
      {showAutoFill && (
        <button 
          className="autofill-button"
          onClick={(e) => {
            e.stopPropagation();
            onAutoFill();
          }}
          title="Auto-fill credentials"
        >
          ⚡
        </button>
      )}
    </div>
  );
};

// Add Credential Component
const AddCredential = ({ onSave, onCancel }) => {
  const [formData, setFormData] = useState({
    domain: '',
    username: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Try to get current tab URL
    getCurrentTabUrl();
  }, []);

  const getCurrentTabUrl = async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        setFormData(prev => ({ ...prev, domain: tab.url }));
      }
    } catch (err) {
      console.error('Error getting tab URL:', err);
    }
  };

  const handlePasswordChange = (password) => {
    setFormData(prev => ({ ...prev, password }));
    if (password) {
      const strength = passwordManager.checkPasswordStrength(password);
      setPasswordStrength(strength);
    } else {
      setPasswordStrength(null);
    }
  };

  const handleGeneratePassword = () => {
    const generated = passwordManager.generatePassword();
    handlePasswordChange(generated);
    setShowPassword(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (formData.domain && formData.username && formData.password) {
      setLoading(true);
      try {
        await onSave(formData);
      } catch (err) {
        console.error('Save error:', err);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="add-credential">
      <h3>Add New Password</h3>
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Website URL</label>
          <input
            type="url"
            value={formData.domain}
            onChange={(e) => setFormData(prev => ({ ...prev, domain: e.target.value }))}
            placeholder="https://example.com"
            required
          />
        </div>

        <div className="form-group">
          <label>Username / Email</label>
          <input
            type="text"
            value={formData.username}
            onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
            placeholder="john@example.com"
            required
          />
        </div>

        <div className="form-group">
          <label>Password</label>
          <div className="password-input-group">
            <input
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={(e) => handlePasswordChange(e.target.value)}
              placeholder="Enter password"
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="toggle-password"
            >
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
            <button
              type="button"
              onClick={handleGeneratePassword}
              className="generate-password"
              title="Generate password"
            >
              🎲
            </button>
          </div>

          {passwordStrength && (
            <div className={`password-strength strength-${passwordStrength.level}`}>
              <div className="strength-bar">
                <div className="strength-fill" style={{ width: `${passwordStrength.score}%` }}></div>
              </div>
              <span>{passwordStrength.level}</span>
            </div>
          )}
        </div>

        <div className="form-actions">
          <button type="button" onClick={onCancel} disabled={loading}>
            Cancel
          </button>
          <button type="submit" disabled={loading}>
            {loading ? 'Saving...' : 'Save Password'}
          </button>
        </div>
      </form>
    </div>
  );
};

// Password Generator Component
const PasswordGenerator = () => {
  const [password, setPassword] = useState('');
  const [options, setOptions] = useState({
    length: 20,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilar: true
  });
  const [strength, setStrength] = useState(null);
  const [copied, setCopied] = useState(false);

  const generatePassword = useCallback(() => {
    const generated = passwordManager.generatePassword(options.length, options);
    setPassword(generated);
    const strengthCheck = passwordManager.checkPasswordStrength(generated);
    setStrength(strengthCheck);
    setCopied(false);
  }, [options]);

  useEffect(() => {
    generatePassword();
  }, []);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  };

  return (
    <div className="password-generator">
      <h3>Password Generator</h3>

      <div className="generated-password">
        <input 
          type="text" 
          value={password} 
          readOnly 
        />
        <button onClick={copyToClipboard} className="copy-button">
          {copied ? '✓' : '📋'}
        </button>
        <button onClick={generatePassword} className="regenerate-button">
          🔄
        </button>
      </div>

      {strength && (
        <div className={`password-strength strength-${strength.level}`}>
          <div className="strength-bar">
            <div className="strength-fill" style={{ width: `${strength.score}%` }}></div>
          </div>
          <span>Strength: {strength.level}</span>
        </div>
      )}

      <div className="generator-options">
        <div className="option-group">
          <label>
            Length: {options.length}
            <input
              type="range"
              min="8"
              max="50"
              value={options.length}
              onChange={(e) => setOptions(prev => ({ ...prev, length: parseInt(e.target.value) }))}
            />
          </label>
        </div>

        <div className="option-group">
          <label>
            <input
              type="checkbox"
              checked={options.includeUppercase}
              onChange={(e) => setOptions(prev => ({ ...prev, includeUppercase: e.target.checked }))}
            />
            Uppercase (A-Z)
          </label>
        </div>

        <div className="option-group">
          <label>
            <input
              type="checkbox"
              checked={options.includeLowercase}
              onChange={(e) => setOptions(prev => ({ ...prev, includeLowercase: e.target.checked }))}
            />
            Lowercase (a-z)
          </label>
        </div>

        <div className="option-group">
          <label>
            <input
              type="checkbox"
              checked={options.includeNumbers}
              onChange={(e) => setOptions(prev => ({ ...prev, includeNumbers: e.target.checked }))}
            />
            Numbers (0-9)
          </label>
        </div>

        <div className="option-group">
          <label>
            <input
              type="checkbox"
              checked={options.includeSymbols}
              onChange={(e) => setOptions(prev => ({ ...prev, includeSymbols: e.target.checked }))}
            />
            Symbols (!@#$...)
          </label>
        </div>

        <div className="option-group">
          <label>
            <input
              type="checkbox"
              checked={options.excludeSimilar}
              onChange={(e) => setOptions(prev => ({ ...prev, excludeSimilar: e.target.checked }))}
            />
            Exclude similar characters (0, O, l, 1)
          </label>
        </div>
      </div>

      <button onClick={generatePassword} className="generate-button">
        Generate New Password
      </button>
    </div>
  );
};

// Security Settings Component
const SecuritySettings = () => {
  const [settings, setSettings] = useState({
    autoLockMinutes: 5,
    checkBreaches: true,
    warnPhishing: true
  });

  const handleExport = async () => {
    try {
      const data = await passwordManager.exportCredentials();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `passwords-backup-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
    }
  };

  const handleImport = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
      const text = await file.text();
      const data = JSON.parse(text);
      
      // Show dialog to get master password
      const masterPassword = prompt('Enter master password for imported data:');
      if (masterPassword) {
        const count = await passwordManager.importCredentials(data, masterPassword);
        alert(`Successfully imported ${count} credentials`);
      }
    } catch (err) {
      alert('Import failed: ' + err.message);
    }
  };

  return (
    <div className="security-settings">
      <h3>Security Settings</h3>

      <div className="settings-section">
        <h4>Auto-Lock</h4>
        <label>
          Lock after inactivity (minutes):
          <input
            type="number"
            min="1"
            max="60"
            value={settings.autoLockMinutes}
            onChange={(e) => setSettings(prev => ({ ...prev, autoLockMinutes: parseInt(e.target.value) }))}
          />
        </label>
      </div>

      <div className="settings-section">
        <h4>Security Features</h4>
        <label>
          <input
            type="checkbox"
            checked={settings.checkBreaches}
            onChange={(e) => setSettings(prev => ({ ...prev, checkBreaches: e.target.checked }))}
          />
          Check passwords against known breaches
        </label>
        <label>
          <input
            type="checkbox"
            checked={settings.warnPhishing}
            onChange={(e) => setSettings(prev => ({ ...prev, warnPhishing: e.target.checked }))}
          />
          Warn about suspicious login pages
        </label>
      </div>

      <div className="settings-section">
        <h4>Backup & Restore</h4>
        <button onClick={handleExport} className="export-button">
          📥 Export Passwords
        </button>
        <label className="import-button">
          📤 Import Passwords
          <input type="file" accept=".json" onChange={handleImport} style={{ display: 'none' }} />
        </label>
      </div>

      <div className="settings-section">
        <h4>About</h4>
        <p>Secure password manager with AI-powered features</p>
        <small>All data is encrypted locally using AES-256-GCM</small>
      </div>
    </div>
  );
};

// Credential Details Component
const CredentialDetails = ({ credential, onClose, onDelete }) => {
  const [decrypted, setDecrypted] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(true);
  const [analysis, setAnalysis] = useState(null);

  useEffect(() => {
    loadCredential();
  }, [credential]);

  const loadCredential = async () => {
    try {
      const dec = await passwordManager.decrypt(credential.encrypted);
      setDecrypted(dec);
      
      // Analyze password security
      const result = await aiPasswordAgent.analyzePasswordSecurity(dec.password);
      setAnalysis(result);
    } catch (err) {
      console.error('Decrypt error:', err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      // Show notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'assets/icon128.png',
        title: 'Copied!',
        message: 'Copied to clipboard'
      });
    } catch (err) {
      console.error('Copy failed:', err);
    }
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="credential-details-modal">
      <div className="modal-backdrop" onClick={onClose}></div>
      <div className="modal-content">
        <div className="modal-header">
          <h3>{credential.domain}</h3>
          <button onClick={onClose} className="close-button">✕</button>
        </div>

        <div className="credential-field">
          <label>Username</label>
          <div className="field-value">
            <span>{decrypted?.username}</span>
            <button onClick={() => copyToClipboard(decrypted?.username)}>📋</button>
          </div>
        </div>

        <div className="credential-field">
          <label>Password</label>
          <div className="field-value">
            <span>{showPassword ? decrypted?.password : '••••••••'}</span>
            <button onClick={() => setShowPassword(!showPassword)}>
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
            <button onClick={() => copyToClipboard(decrypted?.password)}>📋</button>
          </div>
        </div>

        {analysis && (
          <div className="password-analysis">
            <div className={`strength-indicator strength-${analysis.strength.level}`}>
              Password Strength: {analysis.strength.level}
            </div>
            
            {analysis.breached && (
              <div className="breach-warning">
                ⚠️ This password has been found in data breaches!
              </div>
            )}

            {analysis.recommendations.map((rec, index) => (
              <div key={index} className={`recommendation rec-${rec.type}`}>
                {rec.message}
              </div>
            ))}
          </div>
        )}

        <div className="modal-actions">
          <button onClick={() => onDelete(credential.id)} className="delete-button">
            Delete
          </button>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
};

export default PasswordManagerPanel;