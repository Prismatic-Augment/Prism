// Enhanced Password Manager UI Components with Advanced Features

import React, { useState, useEffect, useRef } from 'react';
import passwordManager from './passwordManager.js';
import aiPasswordAgent from './aiPasswordAgent.js';
import { totpManager, EnhancedCredential } from './totpManager.js';
import secureNotesManager from './secureNotes.js';
import passwordAuditManager from './passwordAudit.js';

// TOTP Component
function TOTPManager({ credential }) {
  const [totpCode, setTotpCode] = useState('');
  const [timeRemaining, setTimeRemaining] = useState(30);
  const [showSetup, setShowSetup] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const intervalRef = useRef(null);

  useEffect(() => {
    if (credential.totp) {
      updateTOTP();
      intervalRef.current = setInterval(updateTOTP, 1000);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [credential]);

  const updateTOTP = async () => {
    const enhancedCred = new EnhancedCredential(credential);
    const totp = await enhancedCred.getCurrentTOTP();
    if (totp) {
      setTotpCode(totp.code);
      setTimeRemaining(totp.timeRemaining);
    }
  };

  const setupTOTP = async () => {
    if (!totpSecret) return;
    
    const enhancedCred = new EnhancedCredential(credential);
    await enhancedCred.addTOTP(totpSecret);
    await passwordManager.updateCredential(credential.id, credential);
    setShowSetup(false);
    updateTOTP();
  };

  const copyTOTP = () => {
    navigator.clipboard.writeText(totpCode);
    // Show toast notification
  };

  if (!credential.totp && !showSetup) {
    return (
      <button 
        className="totp-setup-btn"
        onClick={() => setShowSetup(true)}
      >
        <span className="icon">🔐</span> Enable 2FA
      </button>
    );
  }

  if (showSetup) {
    return (
      <div className="totp-setup">
        <h4>Setup Two-Factor Authentication</h4>
        <input
          type="text"
          placeholder="Enter TOTP secret or scan QR code"
          value={totpSecret}
          onChange={(e) => setTotpSecret(e.target.value)}
          className="totp-secret-input"
        />
        <div className="totp-actions">
          <button onClick={setupTOTP} className="btn-primary">Enable 2FA</button>
          <button onClick={() => setShowSetup(false)} className="btn-secondary">Cancel</button>
        </div>
      </div>
    );
  }

  return (
    <div className="totp-display">
      <div className="totp-code" onClick={copyTOTP}>
        <span className="code">{totpCode}</span>
        <div className="time-remaining">
          <div 
            className="progress"
            style={{ width: `${(timeRemaining / 30) * 100}%` }}
          />
        </div>
      </div>
      <button 
        className="totp-autofill"
        onClick={async () => {
          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          const enhancedCred = new EnhancedCredential(credential);
          await enhancedCred.autoFillTOTP(tabs[0].id);
        }}
      >
        Auto-fill
      </button>
    </div>
  );
}

// Secure Notes Component
function SecureNotesPanel() {
  const [notes, setNotes] = useState([]);
  const [selectedNote, setSelectedNote] = useState(null);
  const [showNewNote, setShowNewNote] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedTemplate, setSelectedTemplate] = useState(null);

  useEffect(() => {
    loadNotes();
  }, []);

  const loadNotes = async () => {
    const allNotes = await secureNotesManager.getAllNotes();
    setNotes(allNotes);
  };

  const createNote = async (noteData) => {
    await secureNotesManager.createNote(noteData);
    await loadNotes();
    setShowNewNote(false);
  };

  const templates = secureNotesManager.getTemplates();

  return (
    <div className="secure-notes-panel">
      <div className="notes-header">
        <h3>Secure Notes</h3>
        <button 
          className="btn-add"
          onClick={() => setShowNewNote(true)}
        >
          <span className="icon">+</span> New Note
        </button>
      </div>

      <div className="notes-controls">
        <input
          type="text"
          placeholder="Search notes..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
        <select 
          value={selectedCategory}
          onChange={(e) => setSelectedCategory(e.target.value)}
          className="category-filter"
        >
          <option value="all">All Categories</option>
          {secureNotesManager.categories.map(cat => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
        </select>
      </div>

      <div className="notes-list">
        {notes
          .filter(note => 
            selectedCategory === 'all' || note.category === selectedCategory
          )
          .map(note => (
            <div 
              key={note.id}
              className="note-item"
              onClick={() => setSelectedNote(note)}
            >
              <div className="note-icon">{getCategoryIcon(note.category)}</div>
              <div className="note-info">
                <h4>{note.title}</h4>
                <span className="note-meta">
                  {note.category} • {formatDate(note.modified)}
                </span>
              </div>
              {note.metadata.hasAttachments && (
                <span className="attachment-indicator">📎</span>
              )}
            </div>
          ))}
      </div>

      {showNewNote && (
        <NewNoteModal
          templates={templates}
          onSave={createNote}
          onClose={() => setShowNewNote(false)}
        />
      )}

      {selectedNote && (
        <NoteDetailModal
          noteId={selectedNote.id}
          onClose={() => setSelectedNote(null)}
          onUpdate={loadNotes}
        />
      )}
    </div>
  );
}

// Password Audit Dashboard Component
function PasswordAuditDashboard() {
  const [auditData, setAuditData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState('overview'); // overview, details, history
  const [stats, setStats] = useState(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    const statistics = await passwordAuditManager.getPasswordStatistics();
    setStats(statistics);
  };

  const runAudit = async () => {
    setLoading(true);
    try {
      const results = await passwordAuditManager.performFullAudit();
      setAuditData(results);
      await loadStats();
    } finally {
      setLoading(false);
    }
  };

  const exportReport = async (format) => {
    const report = await passwordAuditManager.exportAuditReport(format);
    const blob = new Blob([report], { 
      type: format === 'json' ? 'application/json' : 'text/csv' 
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `password-audit-${Date.now()}.${format}`;
    a.click();
  };

  return (
    <div className="audit-dashboard">
      <div className="audit-header">
        <h3>Security Dashboard</h3>
        <div className="audit-actions">
          <button 
            className="btn-audit"
            onClick={runAudit}
            disabled={loading}
          >
            {loading ? 'Auditing...' : 'Run Security Audit'}
          </button>
          {auditData && (
            <div className="export-menu">
              <button className="btn-export">Export Report ⬇</button>
              <div className="export-options">
                <button onClick={() => exportReport('json')}>JSON</button>
                <button onClick={() => exportReport('csv')}>CSV</button>
              </div>
            </div>
          )}
        </div>
      </div>

      {auditData && (
        <>
          <div className="security-score">
            <div className="score-circle">
              <svg viewBox="0 0 200 200">
                <circle
                  cx="100"
                  cy="100"
                  r="90"
                  fill="none"
                  stroke="#2a2a2a"
                  strokeWidth="20"
                />
                <circle
                  cx="100"
                  cy="100"
                  r="90"
                  fill="none"
                  stroke={getScoreColor(auditData.summary.securityScore)}
                  strokeWidth="20"
                  strokeDasharray={`${(auditData.summary.securityScore / 100) * 565} 565`}
                  transform="rotate(-90 100 100)"
                />
              </svg>
              <div className="score-text">
                <span className="score-number">{auditData.summary.securityScore}</span>
                <span className="score-label">Security Score</span>
              </div>
            </div>
          </div>

          <div className="audit-summary">
            <div className="summary-card">
              <span className="card-icon">🔑</span>
              <span className="card-value">{auditData.summary.totalPasswords}</span>
              <span className="card-label">Total Passwords</span>
            </div>
            <div className="summary-card warning">
              <span className="card-icon">⚠️</span>
              <span className="card-value">{auditData.summary.weakPasswords}</span>
              <span className="card-label">Weak Passwords</span>
            </div>
            <div className="summary-card danger">
              <span className="card-icon">🚨</span>
              <span className="card-value">{auditData.summary.breachedPasswords}</span>
              <span className="card-label">Breached</span>
            </div>
            <div className="summary-card">
              <span className="card-icon">♻️</span>
              <span className="card-value">{auditData.summary.reusedPasswords}</span>
              <span className="card-label">Reused</span>
            </div>
          </div>

          <div className="audit-recommendations">
            <h4>Recommendations</h4>
            {auditData.recommendations.map((rec, index) => (
              <div key={index} className={`recommendation ${rec.priority}`}>
                <div className="rec-header">
                  <span className="priority-badge">{rec.priority}</span>
                  <h5>{rec.title}</h5>
                </div>
                <p>{rec.description}</p>
                <div className="rec-action">
                  <span>{rec.action}</span>
                  <button className="btn-fix">Fix Now →</button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {stats && view === 'overview' && (
        <div className="password-stats">
          <h4>Password Statistics</h4>
          <div className="stats-charts">
            <StrengthChart data={stats.byStrength} />
            <AgeChart data={stats.byAge} />
            <DomainChart data={stats.byDomain} />
          </div>
        </div>
      )}
    </div>
  );
}

// Helper Components
function NewNoteModal({ templates, onSave, onClose }) {
  const [noteData, setNoteData] = useState({
    title: '',
    category: 'other',
    content: '',
    tags: [],
    customFields: {}
  });
  const [selectedTemplate, setSelectedTemplate] = useState(null);

  const applyTemplate = (templateKey) => {
    const template = templates[templateKey];
    setNoteData({
      ...noteData,
      title: template.title,
      category: template.category,
      customFields: template.customFields
    });
    setSelectedTemplate(templateKey);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h3>Create Secure Note</h3>
        
        <div className="template-selector">
          <label>Use Template:</label>
          <select onChange={(e) => applyTemplate(e.target.value)}>
            <option value="">No template</option>
            {Object.keys(templates).map(key => (
              <option key={key} value={key}>
                {templates[key].title}
              </option>
            ))}
          </select>
        </div>

        <input
          type="text"
          placeholder="Note title"
          value={noteData.title}
          onChange={(e) => setNoteData({...noteData, title: e.target.value})}
        />

        <select
          value={noteData.category}
          onChange={(e) => setNoteData({...noteData, category: e.target.value})}
        >
          {secureNotesManager.categories.map(cat => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
        </select>

        {!selectedTemplate && (
          <textarea
            placeholder="Note content..."
            value={noteData.content}
            onChange={(e) => setNoteData({...noteData, content: e.target.value})}
            rows={10}
          />
        )}

        {selectedTemplate && (
          <div className="custom-fields">
            {Object.entries(noteData.customFields).map(([key, value]) => (
              <div key={key} className="field-group">
                <label>{formatFieldName(key)}</label>
                <input
                  type={getFieldType(key)}
                  value={value}
                  onChange={(e) => setNoteData({
                    ...noteData,
                    customFields: {
                      ...noteData.customFields,
                      [key]: e.target.value
                    }
                  })}
                />
              </div>
            ))}
          </div>
        )}

        <div className="modal-actions">
          <button onClick={() => onSave(noteData)} className="btn-primary">
            Save Note
          </button>
          <button onClick={onClose} className="btn-secondary">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// Utility functions
function getCategoryIcon(category) {
  const icons = {
    personal: '👤',
    financial: '💳',
    medical: '🏥',
    work: '💼',
    legal: '⚖️',
    crypto: '₿',
    other: '📄'
  };
  return icons[category] || '📄';
}

function formatDate(timestamp) {
  return new Date(timestamp).toLocaleDateString();
}

function getScoreColor(score) {
  if (score >= 80) return '#4caf50';
  if (score >= 60) return '#ff9800';
  if (score >= 40) return '#f44336';
  return '#d32f2f';
}

function formatFieldName(fieldName) {
  return fieldName
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase());
}

function getFieldType(fieldName) {
  if (fieldName.includes('password') || fieldName.includes('pin')) return 'password';
  if (fieldName.includes('date')) return 'date';
  if (fieldName.includes('email')) return 'email';
  return 'text';
}

// Export enhanced components
export { 
  TOTPManager, 
  SecureNotesPanel, 
  PasswordAuditDashboard,
  NewNoteModal
};