// Secure Notes Module - Store sensitive information beyond passwords

import passwordManager from './passwordManager.js';

class SecureNotesManager {
  constructor() {
    this.categories = [
      'personal',
      'financial',
      'medical',
      'work',
      'legal',
      'crypto',
      'other'
    ];
  }

  // Create a new secure note
  async createNote(noteData) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const note = {
      id: crypto.randomUUID(),
      title: noteData.title,
      category: noteData.category || 'other',
      created: Date.now(),
      modified: Date.now(),
      tags: noteData.tags || [],
      encrypted: await passwordManager.encrypt({
        content: noteData.content,
        attachments: noteData.attachments || [],
        customFields: noteData.customFields || {}
      }),
      metadata: {
        hasAttachments: (noteData.attachments?.length || 0) > 0,
        lastAccessed: null,
        accessCount: 0
      }
    };

    // Save to storage
    const notes = await this.getAllNotes();
    notes.push(note);
    await chrome.storage.local.set({ secureNotes: notes });

    return note.id;
  }

  // Get all notes (encrypted)
  async getAllNotes() {
    const data = await chrome.storage.local.get('secureNotes');
    return data.secureNotes || [];
  }

  // Get decrypted note by ID
  async getNote(noteId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const notes = await this.getAllNotes();
    const note = notes.find(n => n.id === noteId);

    if (!note) {
      throw new Error('Note not found');
    }

    // Decrypt content
    const decrypted = await passwordManager.decrypt(note.encrypted);

    // Update access metadata
    note.metadata.lastAccessed = Date.now();
    note.metadata.accessCount++;
    
    const updatedNotes = notes.map(n => n.id === noteId ? note : n);
    await chrome.storage.local.set({ secureNotes: updatedNotes });

    return {
      id: note.id,
      title: note.title,
      category: note.category,
      created: note.created,
      modified: note.modified,
      tags: note.tags,
      content: decrypted.content,
      attachments: decrypted.attachments,
      customFields: decrypted.customFields,
      metadata: note.metadata
    };
  }

  // Update note
  async updateNote(noteId, updates) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const notes = await this.getAllNotes();
    const noteIndex = notes.findIndex(n => n.id === noteId);

    if (noteIndex === -1) {
      throw new Error('Note not found');
    }

    const existingNote = notes[noteIndex];
    
    // Prepare updated data
    const updatedNote = {
      ...existingNote,
      title: updates.title || existingNote.title,
      category: updates.category || existingNote.category,
      tags: updates.tags || existingNote.tags,
      modified: Date.now()
    };

    // Re-encrypt if content changed
    if (updates.content !== undefined || updates.attachments !== undefined || updates.customFields !== undefined) {
      const decrypted = await passwordManager.decrypt(existingNote.encrypted);
      updatedNote.encrypted = await passwordManager.encrypt({
        content: updates.content !== undefined ? updates.content : decrypted.content,
        attachments: updates.attachments !== undefined ? updates.attachments : decrypted.attachments,
        customFields: updates.customFields !== undefined ? updates.customFields : decrypted.customFields
      });
    }

    notes[noteIndex] = updatedNote;
    await chrome.storage.local.set({ secureNotes: notes });

    return updatedNote.id;
  }

  // Delete note
  async deleteNote(noteId) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const notes = await this.getAllNotes();
    const filtered = notes.filter(n => n.id !== noteId);

    if (filtered.length === notes.length) {
      throw new Error('Note not found');
    }

    await chrome.storage.local.set({ secureNotes: filtered });
    return true;
  }

  // Search notes
  async searchNotes(query, options = {}) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const notes = await this.getAllNotes();
    const results = [];

    for (const note of notes) {
      // Search in metadata
      let matches = false;

      // Title search
      if (note.title.toLowerCase().includes(query.toLowerCase())) {
        matches = true;
      }

      // Category filter
      if (options.category && note.category !== options.category) {
        continue;
      }

      // Tag search
      if (options.tags) {
        const hasAllTags = options.tags.every(tag => note.tags.includes(tag));
        if (!hasAllTags) continue;
      }

      // Date range filter
      if (options.dateFrom && note.created < options.dateFrom) continue;
      if (options.dateTo && note.created > options.dateTo) continue;

      // Search in content if requested and title matches
      if (matches || options.searchContent) {
        const decrypted = await passwordManager.decrypt(note.encrypted);
        
        if (decrypted.content.toLowerCase().includes(query.toLowerCase()) ||
            Object.values(decrypted.customFields).some(value => 
              String(value).toLowerCase().includes(query.toLowerCase())
            )) {
          matches = true;
        }
      }

      if (matches) {
        results.push({
          id: note.id,
          title: note.title,
          category: note.category,
          created: note.created,
          modified: note.modified,
          tags: note.tags,
          metadata: note.metadata,
          // Don't include decrypted content in search results
          snippet: await this.generateSnippet(note, query)
        });
      }
    }

    return results;
  }

  // Generate safe snippet for search results
  async generateSnippet(note, query) {
    const decrypted = await passwordManager.decrypt(note.encrypted);
    const content = decrypted.content.toLowerCase();
    const queryLower = query.toLowerCase();
    const index = content.indexOf(queryLower);

    if (index === -1) return '';

    const start = Math.max(0, index - 50);
    const end = Math.min(content.length, index + query.length + 50);
    
    let snippet = decrypted.content.substring(start, end);
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';

    return snippet;
  }

  // Attach file to note (base64 encoded)
  async attachFile(noteId, file) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const maxSize = 5 * 1024 * 1024; // 5MB limit
    if (file.size > maxSize) {
      throw new Error('File too large (max 5MB)');
    }

    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = async (e) => {
        const attachment = {
          id: crypto.randomUUID(),
          name: file.name,
          type: file.type,
          size: file.size,
          data: e.target.result.split(',')[1], // Remove data:type;base64, prefix
          created: Date.now()
        };

        try {
          const note = await this.getNote(noteId);
          note.attachments.push(attachment);
          
          await this.updateNote(noteId, {
            attachments: note.attachments
          });

          resolve(attachment.id);
        } catch (error) {
          reject(error);
        }
      };

      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsDataURL(file);
    });
  }

  // Get attachment
  async getAttachment(noteId, attachmentId) {
    const note = await this.getNote(noteId);
    const attachment = note.attachments.find(a => a.id === attachmentId);

    if (!attachment) {
      throw new Error('Attachment not found');
    }

    return attachment;
  }

  // Export notes
  async exportNotes(noteIds = null) {
    if (!passwordManager.isUnlocked) {
      throw new Error('Password manager is locked');
    }

    const allNotes = await this.getAllNotes();
    const notes = noteIds 
      ? allNotes.filter(n => noteIds.includes(n.id))
      : allNotes;

    const salt = await chrome.storage.local.get('passwordSalt');

    return {
      version: '1.0',
      type: 'secure_notes',
      salt: salt.passwordSalt,
      notes: notes,
      exported: new Date().toISOString()
    };
  }

  // Import notes
  async importNotes(data, masterPassword) {
    if (!data.version || !data.salt || !data.notes) {
      throw new Error('Invalid import data format');
    }

    if (data.type !== 'secure_notes') {
      throw new Error('Invalid data type');
    }

    // Verify the master password with the imported salt
    const importKey = await passwordManager.deriveKey(masterPassword, new Uint8Array(data.salt));
    
    // Try to decrypt first note to verify password
    if (data.notes.length > 0) {
      try {
        await passwordManager.decrypt(data.notes[0].encrypted, importKey);
      } catch {
        throw new Error('Invalid master password for import data');
      }
    }

    // Import notes
    const existingNotes = await this.getAllNotes();
    const mergedNotes = [...existingNotes, ...data.notes];
    
    await chrome.storage.local.set({ secureNotes: mergedNotes });
    return data.notes.length;
  }

  // Template system for common note types
  getTemplates() {
    return {
      creditCard: {
        title: 'Credit Card',
        category: 'financial',
        customFields: {
          cardNumber: '',
          cardholderName: '',
          expiryDate: '',
          cvv: '',
          pin: '',
          bank: '',
          type: 'Visa/Mastercard/Amex',
          creditLimit: '',
          notes: ''
        }
      },
      bankAccount: {
        title: 'Bank Account',
        category: 'financial',
        customFields: {
          bankName: '',
          accountNumber: '',
          routingNumber: '',
          swiftCode: '',
          iban: '',
          accountType: 'Checking/Savings',
          branch: '',
          notes: ''
        }
      },
      passport: {
        title: 'Passport',
        category: 'personal',
        customFields: {
          passportNumber: '',
          fullName: '',
          nationality: '',
          dateOfBirth: '',
          placeOfBirth: '',
          issueDate: '',
          expiryDate: '',
          issuingAuthority: '',
          notes: ''
        }
      },
      cryptoWallet: {
        title: 'Crypto Wallet',
        category: 'crypto',
        customFields: {
          walletType: 'Hot/Cold/Hardware',
          walletAddress: '',
          privateKey: '',
          seedPhrase: '',
          passphrase: '',
          currency: '',
          exchange: '',
          notes: ''
        }
      },
      wifiNetwork: {
        title: 'WiFi Network',
        category: 'other',
        customFields: {
          networkName: '',
          password: '',
          securityType: 'WPA2/WPA3',
          routerIP: '',
          adminUsername: '',
          adminPassword: '',
          notes: ''
        }
      },
      medicalRecord: {
        title: 'Medical Record',
        category: 'medical',
        customFields: {
          patientName: '',
          dateOfBirth: '',
          bloodType: '',
          allergies: '',
          medications: '',
          conditions: '',
          emergencyContact: '',
          insuranceInfo: '',
          notes: ''
        }
      }
    };
  }
}

// Export singleton instance
const secureNotesManager = new SecureNotesManager();
export default secureNotesManager;