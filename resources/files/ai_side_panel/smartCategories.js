// Smart Categories Module - AI-powered automatic password categorization

import passwordManager from './passwordManager.js';
import aiPasswordAgent from './aiPasswordAgent.js';

class SmartCategoriesManager {
  constructor() {
    this.categories = {
      social: {
        name: 'Social Media',
        icon: '💬',
        patterns: ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'reddit', 'pinterest', 'snapchat'],
        keywords: ['social', 'profile', 'friends', 'follow', 'share', 'post']
      },
      financial: {
        name: 'Financial',
        icon: '💳',
        patterns: ['bank', 'paypal', 'stripe', 'coinbase', 'robinhood', 'venmo', 'cashapp'],
        keywords: ['payment', 'finance', 'money', 'invest', 'trading', 'crypto', 'wallet']
      },
      work: {
        name: 'Work',
        icon: '💼',
        patterns: ['slack', 'teams', 'zoom', 'jira', 'confluence', 'github', 'gitlab'],
        keywords: ['work', 'office', 'company', 'corporate', 'business', 'project']
      },
      entertainment: {
        name: 'Entertainment',
        icon: '🎮',
        patterns: ['netflix', 'spotify', 'youtube', 'twitch', 'steam', 'epic', 'playstation'],
        keywords: ['watch', 'stream', 'game', 'play', 'music', 'video', 'movie']
      },
      shopping: {
        name: 'Shopping',
        icon: '🛒',
        patterns: ['amazon', 'ebay', 'etsy', 'shopify', 'walmart', 'target', 'bestbuy'],
        keywords: ['shop', 'buy', 'store', 'cart', 'order', 'purchase', 'retail']
      },
      utilities: {
        name: 'Utilities',
        icon: '🔧',
        patterns: ['google', 'microsoft', 'apple', 'dropbox', 'drive', 'icloud'],
        keywords: ['cloud', 'storage', 'email', 'utility', 'service', 'tool']
      },
      education: {
        name: 'Education',
        icon: '📚',
        patterns: ['coursera', 'udemy', 'khan', 'edx', 'blackboard', 'canvas'],
        keywords: ['learn', 'course', 'education', 'school', 'university', 'study']
      },
      health: {
        name: 'Health',
        icon: '🏥',
        patterns: ['mychart', 'healthgrades', 'webmd', 'fitbit', 'myfitnesspal'],
        keywords: ['health', 'medical', 'doctor', 'fitness', 'wellness', 'appointment']
      },
      travel: {
        name: 'Travel',
        icon: '✈️',
        patterns: ['booking', 'airbnb', 'expedia', 'kayak', 'uber', 'lyft'],
        keywords: ['travel', 'flight', 'hotel', 'trip', 'vacation', 'transport']
      },
      development: {
        name: 'Development',
        icon: '👨‍💻',
        patterns: ['github', 'stackoverflow', 'npm', 'docker', 'aws', 'azure'],
        keywords: ['code', 'develop', 'programming', 'api', 'deploy', 'server']
      }
    };

    this.mlModel = null;
    this.modelLoaded = false;
    this.confidenceThreshold = 0.7;
  }

  // Initialize ML model for advanced categorization
  async initializeMLModel() {
    try {
      // In production, load a pre-trained TensorFlow.js model
      // For now, use rule-based system with scoring
      this.modelLoaded = true;
      return true;
    } catch (error) {
      console.error('Failed to load ML model:', error);
      return false;
    }
  }

  // Categorize a credential
  async categorizeCredential(credential) {
    const domain = this.extractDomain(credential.domain);
    const url = credential.domain.toLowerCase();
    
    // Try ML-based categorization first
    if (this.modelLoaded) {
      const mlCategory = await this.mlCategorize(credential);
      if (mlCategory.confidence > this.confidenceThreshold) {
        return {
          category: mlCategory.category,
          confidence: mlCategory.confidence,
          method: 'ml'
        };
      }
    }

    // Fallback to pattern matching
    const scores = {};

    for (const [catKey, catData] of Object.entries(this.categories)) {
      scores[catKey] = 0;

      // Check domain patterns
      for (const pattern of catData.patterns) {
        if (url.includes(pattern)) {
          scores[catKey] += 10;
        }
      }

      // Check keywords in domain
      for (const keyword of catData.keywords) {
        if (url.includes(keyword)) {
          scores[catKey] += 5;
        }
      }

      // Check TLD patterns
      if (catKey === 'education' && url.endsWith('.edu')) {
        scores[catKey] += 20;
      }
      if (catKey === 'work' && (url.endsWith('.com') && url.includes('corp'))) {
        scores[catKey] += 15;
      }
    }

    // Find highest scoring category
    let maxScore = 0;
    let bestCategory = 'utilities'; // default

    for (const [category, score] of Object.entries(scores)) {
      if (score > maxScore) {
        maxScore = score;
        bestCategory = category;
      }
    }

    return {
      category: bestCategory,
      confidence: Math.min(maxScore / 30, 1), // Normalize confidence
      method: 'pattern'
    };
  }

  // ML-based categorization (mock implementation)
  async mlCategorize(credential) {
    // Extract features
    const features = await this.extractFeatures(credential);

    // In production, use TensorFlow.js for prediction
    // For now, simulate with enhanced pattern matching
    const domain = this.extractDomain(credential.domain);
    const tld = domain.split('.').pop();
    
    // Simulate ML confidence based on feature richness
    let confidence = 0.5;
    
    if (features.hasSecureProtocol) confidence += 0.1;
    if (features.domainAge > 365) confidence += 0.1;
    if (features.popularityRank < 10000) confidence += 0.2;
    if (features.hasMultiFactor) confidence += 0.1;

    // Determine category based on "ML analysis"
    const category = await this.inferCategoryFromFeatures(features);

    return {
      category,
      confidence: Math.min(confidence, 0.95)
    };
  }

  // Extract features for ML model
  async extractFeatures(credential) {
    const domain = this.extractDomain(credential.domain);
    const url = new URL(credential.domain);

    const features = {
      domain: domain,
      tld: domain.split('.').pop(),
      hasSecureProtocol: url.protocol === 'https:',
      pathDepth: url.pathname.split('/').length - 1,
      hasSubdomain: url.hostname.split('.').length > 2,
      domainLength: domain.length,
      hasNumbers: /\d/.test(domain),
      hasHyphens: domain.includes('-'),
      // Mock additional features
      domainAge: Math.random() * 3650, // Random 0-10 years
      popularityRank: Math.floor(Math.random() * 100000),
      hasMultiFactor: credential.totp ? true : Math.random() > 0.7,
      securityHeaders: Math.random() > 0.5,
      certificateType: ['DV', 'OV', 'EV'][Math.floor(Math.random() * 3)]
    };

    // Add behavioral features if available
    if (credential.usage) {
      features.loginFrequency = credential.usage.frequency || 0;
      features.lastUsed = credential.usage.lastUsed || 0;
      features.deviceCount = credential.usage.devices?.length || 1;
    }

    return features;
  }

  // Infer category from features
  async inferCategoryFromFeatures(features) {
    // Simulated ML inference logic
    if (features.tld === 'edu' || features.domain.includes('university')) {
      return 'education';
    }

    if (features.certificateType === 'EV' && features.hasSecureProtocol) {
      if (features.domain.includes('bank') || features.domain.includes('pay')) {
        return 'financial';
      }
    }

    if (features.loginFrequency > 10 && features.deviceCount > 2) {
      return 'work';
    }

    if (features.domainAge < 365 && features.hasNumbers) {
      return 'shopping';
    }

    // Default inference based on popularity
    if (features.popularityRank < 1000) {
      return 'social';
    } else if (features.popularityRank < 5000) {
      return 'utilities';
    }

    return 'utilities';
  }

  // Auto-categorize all credentials
  async categorizeAll(updateExisting = false) {
    const credentials = await passwordManager.getAllCredentials();
    const categorized = [];
    let updated = 0;

    for (const credential of credentials) {
      if (!credential.category || updateExisting) {
        const result = await this.categorizeCredential(credential);
        
        if (result.confidence > 0.5) {
          credential.category = result.category;
          credential.categoryConfidence = result.confidence;
          credential.categoryMethod = result.method;
          updated++;
        }
      }
      
      categorized.push(credential);
    }

    // Save updated credentials
    await chrome.storage.local.set({ credentials: categorized });

    return {
      total: credentials.length,
      updated: updated,
      categories: this.summarizeCategories(categorized)
    };
  }

  // Get credentials by category
  async getByCategory(category) {
    const credentials = await passwordManager.getAllCredentials();
    return credentials.filter(c => c.category === category);
  }

  // Get category statistics
  async getCategoryStats() {
    const credentials = await passwordManager.getAllCredentials();
    const stats = {};

    // Initialize stats
    for (const catKey of Object.keys(this.categories)) {
      stats[catKey] = {
        count: 0,
        percentage: 0,
        securityScore: 0,
        recentlyUsed: 0
      };
    }

    // Count and analyze
    for (const credential of credentials) {
      const category = credential.category || 'utilities';
      if (stats[category]) {
        stats[category].count++;
        
        // Add to security score calculation
        if (credential.strength?.score) {
          stats[category].securityScore += credential.strength.score;
        }

        // Check if recently used (last 7 days)
        if (credential.lastUsed && Date.now() - credential.lastUsed < 7 * 24 * 60 * 60 * 1000) {
          stats[category].recentlyUsed++;
        }
      }
    }

    // Calculate percentages and averages
    const total = credentials.length;
    for (const [catKey, catStats] of Object.entries(stats)) {
      catStats.percentage = total > 0 ? (catStats.count / total) * 100 : 0;
      catStats.avgSecurityScore = catStats.count > 0 
        ? Math.round(catStats.securityScore / catStats.count)
        : 0;
    }

    return stats;
  }

  // Suggest category improvements
  async suggestCategoryImprovements() {
    const stats = await this.getCategoryStats();
    const suggestions = [];

    for (const [category, catStats] of Object.entries(stats)) {
      // Suggest enabling 2FA for financial/work accounts
      if ((category === 'financial' || category === 'work') && catStats.count > 0) {
        const credentials = await this.getByCategory(category);
        const no2FA = credentials.filter(c => !c.totp).length;
        
        if (no2FA > 0) {
          suggestions.push({
            type: 'security',
            priority: 'high',
            category: category,
            title: `Enable 2FA for ${this.categories[category].name}`,
            description: `${no2FA} ${this.categories[category].name.toLowerCase()} accounts lack two-factor authentication`,
            action: 'enable_2fa',
            affected: no2FA
          });
        }
      }

      // Suggest password updates for low security scores
      if (catStats.avgSecurityScore < 60 && catStats.count > 0) {
        suggestions.push({
          type: 'password_strength',
          priority: 'medium',
          category: category,
          title: `Strengthen ${this.categories[category].name} Passwords`,
          description: `Average security score is only ${catStats.avgSecurityScore}/100`,
          action: 'update_passwords',
          affected: catStats.count
        });
      }

      // Suggest reviewing unused accounts
      if (catStats.count > 0 && catStats.recentlyUsed === 0) {
        suggestions.push({
          type: 'cleanup',
          priority: 'low',
          category: category,
          title: `Review Unused ${this.categories[category].name} Accounts`,
          description: `No ${this.categories[category].name.toLowerCase()} accounts used in the last week`,
          action: 'review_unused',
          affected: catStats.count
        });
      }
    }

    return suggestions.sort((a, b) => {
      const priorityOrder = { high: 0, medium: 1, low: 2 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
  }

  // Create custom category
  async createCustomCategory(categoryData) {
    const customCategories = await this.getCustomCategories();
    
    const newCategory = {
      id: `custom_${Date.now()}`,
      name: categoryData.name,
      icon: categoryData.icon || '📁',
      patterns: categoryData.patterns || [],
      keywords: categoryData.keywords || [],
      color: categoryData.color || '#666666',
      created: Date.now()
    };

    customCategories.push(newCategory);
    await chrome.storage.local.set({ customCategories });

    // Add to active categories
    this.categories[newCategory.id] = newCategory;

    return newCategory;
  }

  // Get custom categories
  async getCustomCategories() {
    const data = await chrome.storage.local.get('customCategories');
    return data.customCategories || [];
  }

  // Extract domain helper
  extractDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      return hostname.replace('www.', '');
    } catch {
      return url;
    }
  }

  // Summarize categories
  summarizeCategories(credentials) {
    const summary = {};
    
    for (const credential of credentials) {
      const category = credential.category || 'utilities';
      summary[category] = (summary[category] || 0) + 1;
    }

    return summary;
  }

  // Export category mappings
  async exportCategoryMappings() {
    const credentials = await passwordManager.getAllCredentials();
    const mappings = {};

    for (const credential of credentials) {
      if (credential.category) {
        const domain = this.extractDomain(credential.domain);
        mappings[domain] = {
          category: credential.category,
          confidence: credential.categoryConfidence || 1,
          method: credential.categoryMethod || 'manual'
        };
      }
    }

    return {
      version: '1.0',
      mappings: mappings,
      categories: this.categories,
      exported: new Date().toISOString()
    };
  }

  // Import category mappings
  async importCategoryMappings(data) {
    if (!data.version || !data.mappings) {
      throw new Error('Invalid category mappings format');
    }

    const credentials = await passwordManager.getAllCredentials();
    let updated = 0;

    for (const credential of credentials) {
      const domain = this.extractDomain(credential.domain);
      const mapping = data.mappings[domain];

      if (mapping && (!credential.category || mapping.confidence > (credential.categoryConfidence || 0))) {
        credential.category = mapping.category;
        credential.categoryConfidence = mapping.confidence;
        credential.categoryMethod = mapping.method;
        updated++;
      }
    }

    await chrome.storage.local.set({ credentials });

    return { updated };
  }
}

// Export singleton instance
const smartCategoriesManager = new SmartCategoriesManager();

// Initialize ML model on load
smartCategoriesManager.initializeMLModel();

export default smartCategoriesManager;