// Natural Language Commands Module - AI-powered command processing

import passwordManager from './passwordManager.js';
import aiPasswordAgent from './aiPasswordAgent.js';
import smartCategoriesManager from './smartCategories.js';
import passwordAuditManager from './passwordAudit.js';
import secureNotesManager from './secureNotes.js';

class NaturalLanguageProcessor {
  constructor() {
    this.commands = {
      // Password management
      'show': this.showPasswords,
      'find': this.findPassword,
      'search': this.searchPasswords,
      'add': this.addPassword,
      'create': this.createPassword,
      'update': this.updatePassword,
      'change': this.changePassword,
      'delete': this.deletePassword,
      'remove': this.removePassword,
      'generate': this.generatePassword,
      
      // Security
      'audit': this.runAudit,
      'check': this.checkSecurity,
      'secure': this.improveSecuiity,
      'breach': this.checkBreaches,
      
      // Categories
      'categorize': this.categorizePasswords,
      'organize': this.organizePasswords,
      
      // Notes
      'note': this.manageNotes,
      'save': this.saveNote,
      
      // Other
      'help': this.showHelp,
      'export': this.exportData,
      'import': this.importData,
      'lock': this.lockManager,
      'unlock': this.unlockManager
    };

    this.intents = [
      {
        patterns: ['show me', 'list', 'display', 'what are'],
        intent: 'show',
        entities: ['category', 'filter']
      },
      {
        patterns: ['find', 'where is', 'look for', 'search for'],
        intent: 'find',
        entities: ['domain', 'username']
      },
      {
        patterns: ['add', 'create', 'new', 'save'],
        intent: 'add',
        entities: ['domain', 'username', 'password']
      },
      {
        patterns: ['change', 'update', 'modify', 'edit'],
        intent: 'update',
        entities: ['domain', 'field', 'value']
      },
      {
        patterns: ['delete', 'remove', 'trash'],
        intent: 'delete',
        entities: ['domain']
      },
      {
        patterns: ['generate', 'create strong', 'make new'],
        intent: 'generate',
        entities: ['length', 'type']
      },
      {
        patterns: ['audit', 'check security', 'analyze', 'review'],
        intent: 'audit',
        entities: ['scope']
      },
      {
        patterns: ['weak', 'vulnerable', 'at risk', 'insecure'],
        intent: 'findWeak',
        entities: ['category']
      },
      {
        patterns: ['breached', 'compromised', 'leaked'],
        intent: 'checkBreaches',
        entities: []
      },
      {
        patterns: ['categorize', 'organize', 'sort', 'group'],
        intent: 'categorize',
        entities: []
      },
      {
        patterns: ['help', 'what can', 'how to', 'guide'],
        intent: 'help',
        entities: ['topic']
      }
    ];

    this.contextHistory = [];
    this.maxContextLength = 5;
  }

  // Process natural language command
  async processCommand(input) {
    try {
      // Add to context history
      this.contextHistory.push({
        input,
        timestamp: Date.now()
      });

      if (this.contextHistory.length > this.maxContextLength) {
        this.contextHistory.shift();
      }

      // Extract intent and entities
      const parsed = await this.parseInput(input);
      
      if (!parsed.intent) {
        return {
          success: false,
          message: "I didn't understand that command. Try 'help' to see what I can do.",
          suggestions: await this.getSuggestions(input)
        };
      }

      // Execute command
      const result = await this.executeCommand(parsed);

      // Add to context
      this.contextHistory[this.contextHistory.length - 1].result = result;

      return result;

    } catch (error) {
      console.error('NLP processing error:', error);
      return {
        success: false,
        message: `Error: ${error.message}`,
        suggestions: ['Try "help" to see available commands']
      };
    }
  }

  // Parse input to extract intent and entities
  async parseInput(input) {
    const normalized = input.toLowerCase().trim();
    let bestMatch = null;
    let highestScore = 0;

    // Check each intent pattern
    for (const intentConfig of this.intents) {
      for (const pattern of intentConfig.patterns) {
        if (normalized.includes(pattern)) {
          const score = pattern.length / normalized.length;
          if (score > highestScore) {
            highestScore = score;
            bestMatch = intentConfig;
          }
        }
      }
    }

    if (!bestMatch) {
      // Try fuzzy matching
      bestMatch = await this.fuzzyMatchIntent(normalized);
    }

    // Extract entities
    const entities = bestMatch ? await this.extractEntities(input, bestMatch.entities) : {};

    return {
      input: input,
      normalized: normalized,
      intent: bestMatch?.intent,
      entities: entities,
      confidence: highestScore
    };
  }

  // Execute parsed command
  async executeCommand(parsed) {
    const handler = this.commands[parsed.intent];
    
    if (!handler) {
      return {
        success: false,
        message: `Unknown command: ${parsed.intent}`
      };
    }

    return await handler.call(this, parsed.entities, parsed);
  }

  // Command handlers
  async showPasswords(entities, parsed) {
    let credentials = await passwordManager.getAllCredentials();
    let message = '';

    // Apply filters
    if (entities.category) {
      credentials = await smartCategoriesManager.getByCategory(entities.category);
      message = `${entities.category} passwords`;
    } else if (entities.filter === 'weak') {
      const audit = await passwordAuditManager.performFullAudit();
      const weakIds = audit.details
        .filter(d => d.strength.score < 60)
        .map(d => d.id);
      credentials = credentials.filter(c => weakIds.includes(c.id));
      message = 'weak passwords';
    } else if (entities.filter === 'recent') {
      credentials = credentials
        .sort((a, b) => b.lastUsed - a.lastUsed)
        .slice(0, 10);
      message = 'recently used passwords';
    } else {
      message = 'all passwords';
    }

    return {
      success: true,
      message: `Showing ${message}`,
      data: {
        type: 'credentials_list',
        credentials: credentials.map(c => ({
          id: c.id,
          domain: c.domain,
          category: c.category,
          strength: c.strength
        })),
        count: credentials.length
      }
    };
  }

  async findPassword(entities, parsed) {
    const credentials = await passwordManager.getAllCredentials();
    let found = [];

    if (entities.domain) {
      found = credentials.filter(c => 
        c.domain.toLowerCase().includes(entities.domain.toLowerCase())
      );
    } else if (entities.username) {
      // Would need to decrypt to search by username
      for (const cred of credentials) {
        const decrypted = await passwordManager.decrypt(cred.encrypted);
        if (decrypted.username.toLowerCase().includes(entities.username.toLowerCase())) {
          found.push(cred);
        }
      }
    }

    if (found.length === 0) {
      return {
        success: false,
        message: 'No passwords found matching your search',
        suggestions: ['Try searching with a different term']
      };
    }

    return {
      success: true,
      message: `Found ${found.length} password${found.length > 1 ? 's' : ''}`,
      data: {
        type: 'search_results',
        results: found
      }
    };
  }

  async generatePassword(entities, parsed) {
    const options = {
      length: entities.length || 20,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: entities.type !== 'simple',
      excludeSimilar: true,
      excludeAmbiguous: true
    };

    const password = passwordManager.generatePassword(options);
    const strength = passwordManager.checkPasswordStrength(password);

    // Copy to clipboard
    await navigator.clipboard.writeText(password);

    return {
      success: true,
      message: 'Generated a strong password and copied to clipboard',
      data: {
        type: 'generated_password',
        password: password,
        strength: strength,
        copied: true
      }
    };
  }

  async runAudit(entities, parsed) {
    const audit = await passwordAuditManager.performFullAudit();

    return {
      success: true,
      message: `Security audit complete. Score: ${audit.summary.securityScore}/100`,
      data: {
        type: 'audit_result',
        summary: audit.summary,
        recommendations: audit.recommendations.slice(0, 3) // Top 3
      }
    };
  }

  async checkBreaches(entities, parsed) {
    const credentials = await passwordManager.getAllCredentials();
    const breached = [];

    for (const cred of credentials) {
      const decrypted = await passwordManager.decrypt(cred.encrypted);
      const isBreached = await aiPasswordAgent.checkPasswordBreach(decrypted.password);
      
      if (isBreached) {
        breached.push({
          domain: cred.domain,
          username: decrypted.username
        });
      }
    }

    if (breached.length === 0) {
      return {
        success: true,
        message: 'Good news! No passwords found in data breaches.',
        data: {
          type: 'breach_check',
          breached: []
        }
      };
    }

    return {
      success: true,
      message: `⚠️ ${breached.length} password${breached.length > 1 ? 's' : ''} found in data breaches!`,
      data: {
        type: 'breach_check',
        breached: breached,
        action: 'Change these passwords immediately'
      }
    };
  }

  async showHelp(entities, parsed) {
    const helpTopics = {
      general: [
        'Show me all passwords',
        'Find password for amazon',
        'Generate a strong password',
        'Check for weak passwords',
        'Run security audit'
      ],
      security: [
        'Check for breached passwords',
        'Show weak passwords',
        'Enable 2FA for banking sites',
        'Review password security'
      ],
      organization: [
        'Categorize all passwords',
        'Show financial passwords',
        'Find work-related accounts'
      ],
      management: [
        'Add new password',
        'Update password for gmail',
        'Delete old accounts',
        'Export my passwords'
      ]
    };

    const topic = entities.topic || 'general';
    const examples = helpTopics[topic] || helpTopics.general;

    return {
      success: true,
      message: 'Here are some things you can ask me:',
      data: {
        type: 'help',
        examples: examples,
        topics: Object.keys(helpTopics)
      }
    };
  }

  // Entity extraction
  async extractEntities(input, expectedEntities) {
    const entities = {};
    const normalized = input.toLowerCase();

    // Extract categories
    if (expectedEntities.includes('category')) {
      const categories = Object.keys(smartCategoriesManager.categories);
      for (const cat of categories) {
        if (normalized.includes(cat)) {
          entities.category = cat;
          break;
        }
      }
    }

    // Extract domains
    if (expectedEntities.includes('domain')) {
      // Look for common domain patterns
      const domainMatch = input.match(/(?:for |of |on )([\w.-]+\.\w+)/i);
      if (domainMatch) {
        entities.domain = domainMatch[1];
      } else {
        // Try to find known domains
        const credentials = await passwordManager.getAllCredentials();
        for (const cred of credentials) {
          const domain = new URL(cred.domain).hostname.replace('www.', '');
          const simpleName = domain.split('.')[0];
          if (normalized.includes(simpleName)) {
            entities.domain = domain;
            break;
          }
        }
      }
    }

    // Extract numbers
    if (expectedEntities.includes('length')) {
      const lengthMatch = input.match(/(\d+)\s*(?:char|character|digit|letter)/i);
      if (lengthMatch) {
        entities.length = parseInt(lengthMatch[1]);
      }
    }

    // Extract filters
    if (expectedEntities.includes('filter')) {
      if (normalized.includes('weak')) entities.filter = 'weak';
      else if (normalized.includes('strong')) entities.filter = 'strong';
      else if (normalized.includes('recent')) entities.filter = 'recent';
      else if (normalized.includes('old')) entities.filter = 'old';
      else if (normalized.includes('breached')) entities.filter = 'breached';
    }

    return entities;
  }

  // Fuzzy intent matching
  async fuzzyMatchIntent(input) {
    // Simple fuzzy matching based on keywords
    const keywordIntents = {
      'password': 'show',
      'find': 'find',
      'search': 'find',
      'add': 'add',
      'new': 'add',
      'change': 'update',
      'update': 'update',
      'delete': 'delete',
      'remove': 'delete',
      'generate': 'generate',
      'create': 'generate',
      'audit': 'audit',
      'security': 'audit',
      'help': 'help'
    };

    for (const [keyword, intent] of Object.entries(keywordIntents)) {
      if (input.includes(keyword)) {
        return this.intents.find(i => i.intent === intent);
      }
    }

    return null;
  }

  // Get command suggestions
  async getSuggestions(input) {
    const suggestions = [];
    const normalized = input.toLowerCase();

    // Context-based suggestions
    if (normalized.includes('password')) {
      suggestions.push(
        'Show me all passwords',
        'Find password for [website]',
        'Generate a strong password'
      );
    }

    if (normalized.includes('security') || normalized.includes('audit')) {
      suggestions.push(
        'Run security audit',
        'Check for weak passwords',
        'Check for breached passwords'
      );
    }

    if (normalized.includes('add') || normalized.includes('new')) {
      suggestions.push(
        'Add password for [website]',
        'Create new secure note'
      );
    }

    // If no specific suggestions, provide general ones
    if (suggestions.length === 0) {
      suggestions.push(
        'Show me all passwords',
        'Run security audit',
        'Type "help" for more commands'
      );
    }

    return suggestions;
  }

  // Get conversation context
  getContext() {
    return this.contextHistory;
  }

  // Clear context
  clearContext() {
    this.contextHistory = [];
  }

  // Train custom intents (for future ML integration)
  async trainIntent(examples, intent) {
    // Store training data for future ML model
    const training = await chrome.storage.local.get('nlpTraining') || {};
    
    if (!training[intent]) {
      training[intent] = [];
    }

    training[intent].push(...examples);
    await chrome.storage.local.set({ nlpTraining: training });

    return {
      success: true,
      message: `Trained ${examples.length} examples for intent: ${intent}`
    };
  }

  // Export command for voice assistants
  formatForVoiceAssistant(result) {
    let spoken = result.message;

    if (result.data) {
      switch (result.data.type) {
        case 'credentials_list':
          spoken += `. You have ${result.data.count} passwords.`;
          break;
        case 'generated_password':
          spoken += `. The password strength is ${result.data.strength.level}.`;
          break;
        case 'audit_result':
          spoken += `. ${result.data.recommendations.length} recommendations available.`;
          break;
      }
    }

    return {
      text: result.message,
      speech: spoken,
      card: result.data
    };
  }
}

// Create singleton instance
const nlpProcessor = new NaturalLanguageProcessor();

// Export for use in UI
export default nlpProcessor;