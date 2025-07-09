// AI Password Agent Module
import passwordManager from './passwordManager.js';

class AIPasswordAgent {
  constructor() {
    this.isActive = true;
    this.currentTab = null;
    this.detectedForms = new Map();
    this.breachCache = new Map();
  }

  // Detect login forms on a page
  async detectLoginForms(tabId) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: this.findLoginFormsInPage
      });

      if (results && results[0]?.result) {
        const forms = results[0].result;
        this.detectedForms.set(tabId, forms);
        return forms;
      }
      return [];
    } catch (error) {
      console.error('Error detecting login forms:', error);
      return [];
    }
  }

  // Function to be injected into the page to find login forms
  findLoginFormsInPage() {
    const forms = [];
    const allForms = document.querySelectorAll('form');
    
    allForms.forEach((form, index) => {
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      const usernameInputs = form.querySelectorAll(
        'input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[id*="user"], input[id*="email"]'
      );

      if (passwordInputs.length > 0) {
        const formData = {
          index,
          hasPassword: true,
          passwordFieldCount: passwordInputs.length,
          possibleUsernameFields: [],
          action: form.action || 'current page',
          method: form.method || 'GET',
          isSignup: false
        };

        // Detect username fields
        usernameInputs.forEach(input => {
          if (this.isUsernameField(input)) {
            formData.possibleUsernameFields.push({
              name: input.name,
              id: input.id,
              type: input.type,
              placeholder: input.placeholder
            });
          }
        });

        // Check if it's a signup form
        const formText = form.textContent.toLowerCase();
        if (formText.includes('sign up') || formText.includes('register') || 
            formText.includes('create account') || passwordInputs.length > 1) {
          formData.isSignup = true;
        }

        forms.push(formData);
      }
    });

    // Also check for login fields not in forms
    const standalonePasswords = document.querySelectorAll('input[type="password"]:not(form input)');
    if (standalonePasswords.length > 0) {
      forms.push({
        index: -1,
        hasPassword: true,
        passwordFieldCount: standalonePasswords.length,
        possibleUsernameFields: [],
        isStandalone: true
      });
    }

    return forms;
  }

  // Helper to determine if an input is likely a username field
  isUsernameField(input) {
    const indicators = ['user', 'email', 'login', 'account', 'id', 'member'];
    const searchText = `${input.name} ${input.id} ${input.placeholder} ${input.className}`.toLowerCase();
    
    return indicators.some(indicator => searchText.includes(indicator));
  }

  // Suggest credentials for a specific domain
  async suggestCredentials(domain) {
    try {
      const credentials = await passwordManager.getCredentialsForDomain(domain);
      
      if (credentials.length === 0) {
        return {
          hasCredentials: false,
          suggestions: [],
          message: 'No saved credentials for this site'
        };
      }

      // Sort by last modified (most recent first)
      credentials.sort((a, b) => b.lastModified - a.lastModified);

      return {
        hasCredentials: true,
        suggestions: credentials.map(cred => ({
          id: cred.id,
          username: cred.username,
          lastUsed: new Date(cred.lastModified).toLocaleDateString()
        })),
        message: `Found ${credentials.length} saved credential(s)`
      };
    } catch (error) {
      if (error.message === 'Password manager is locked') {
        return {
          hasCredentials: false,
          suggestions: [],
          message: 'Password manager is locked',
          needsUnlock: true
        };
      }
      throw error;
    }
  }

  // Auto-fill credentials
  async autoFillCredentials(tabId, credentialId) {
    try {
      const credentials = await passwordManager.getAllCredentials();
      const credential = credentials.find(c => c.id === credentialId);
      
      if (!credential) {
        throw new Error('Credential not found');
      }

      const decrypted = await passwordManager.decrypt(credential.encrypted);

      await chrome.scripting.executeScript({
        target: { tabId },
        func: this.fillCredentialsInPage,
        args: [decrypted.username, decrypted.password]
      });

      return { success: true };
    } catch (error) {
      console.error('Auto-fill error:', error);
      return { success: false, error: error.message };
    }
  }

  // Function to be injected to fill credentials
  fillCredentialsInPage(username, password) {
    // Find password fields
    const passwordFields = document.querySelectorAll('input[type="password"]:not([disabled])');
    
    if (passwordFields.length === 0) {
      return { success: false, error: 'No password fields found' };
    }

    // Fill the first visible password field
    const visiblePasswordField = Array.from(passwordFields).find(field => {
      const rect = field.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    });

    if (!visiblePasswordField) {
      return { success: false, error: 'No visible password fields found' };
    }

    // Find username field
    const form = visiblePasswordField.closest('form');
    const searchScope = form || document;
    
    const usernameSelectors = [
      'input[type="email"]:not([disabled])',
      'input[type="text"][name*="user"]:not([disabled])',
      'input[type="text"][name*="email"]:not([disabled])',
      'input[type="text"][id*="user"]:not([disabled])',
      'input[type="text"][id*="email"]:not([disabled])',
      'input[type="text"]:not([disabled])'
    ];

    let usernameField = null;
    for (const selector of usernameSelectors) {
      const fields = searchScope.querySelectorAll(selector);
      for (const field of fields) {
        const rect = field.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          usernameField = field;
          break;
        }
      }
      if (usernameField) break;
    }

    // Fill fields
    if (usernameField) {
      usernameField.value = username;
      usernameField.dispatchEvent(new Event('input', { bubbles: true }));
      usernameField.dispatchEvent(new Event('change', { bubbles: true }));
    }

    visiblePasswordField.value = password;
    visiblePasswordField.dispatchEvent(new Event('input', { bubbles: true }));
    visiblePasswordField.dispatchEvent(new Event('change', { bubbles: true }));

    return { success: true };
  }

  // Analyze password security
  async analyzePasswordSecurity(password) {
    const strength = passwordManager.checkPasswordStrength(password);
    
    // Check if password has been breached
    const breached = await this.checkPasswordBreach(password);
    
    return {
      strength: strength,
      breached: breached,
      recommendations: this.getPasswordRecommendations(strength, breached)
    };
  }

  // Check if password has been in a breach (using k-anonymity)
  async checkPasswordBreach(password) {
    try {
      // Create SHA-1 hash of password
      const encoder = new TextEncoder();
      const data = encoder.encode(password);
      const hashBuffer = await crypto.subtle.digest('SHA-1', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      
      // Check cache first
      if (this.breachCache.has(hashHex)) {
        return this.breachCache.get(hashHex);
      }

      // Use k-anonymity with Have I Been Pwned API
      const prefix = hashHex.substring(0, 5);
      const suffix = hashHex.substring(5);
      
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      const text = await response.text();
      
      const breached = text.split('\n').some(line => {
        const [hash, count] = line.split(':');
        return hash === suffix;
      });

      // Cache result
      this.breachCache.set(hashHex, breached);
      
      return breached;
    } catch (error) {
      console.error('Error checking password breach:', error);
      return false;
    }
  }

  // Get password recommendations
  getPasswordRecommendations(strength, breached) {
    const recommendations = [];

    if (breached) {
      recommendations.push({
        type: 'critical',
        message: 'This password has been found in data breaches. Change it immediately!'
      });
    }

    if (strength.score < 60) {
      recommendations.push({
        type: 'warning',
        message: 'This password is weak. Consider using a stronger password.'
      });
    }

    strength.feedback.forEach(feedback => {
      recommendations.push({
        type: 'suggestion',
        message: feedback
      });
    });

    if (recommendations.length === 0 && strength.score >= 80) {
      recommendations.push({
        type: 'success',
        message: 'This is a strong password!'
      });
    }

    return recommendations;
  }

  // Monitor for suspicious login pages
  async checkPhishingRisk(url) {
    try {
      const domain = new URL(url).hostname;
      
      // Check common phishing indicators
      const risks = [];
      
      // Check for suspicious domain patterns
      if (domain.includes('-') && domain.split('-').some(part => 
        ['google', 'facebook', 'amazon', 'paypal', 'ebay', 'microsoft'].includes(part.toLowerCase())
      )) {
        risks.push('Domain contains suspicious hyphenated brand name');
      }

      // Check for homograph attacks
      if (/[а-яА-Я]/.test(domain)) {
        risks.push('Domain contains Cyrillic characters (possible homograph attack)');
      }

      // Check for excessive subdomains
      const subdomainCount = domain.split('.').length - 2;
      if (subdomainCount > 2) {
        risks.push('Excessive subdomains detected');
      }

      // Check if using IP address instead of domain
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        risks.push('Site is using IP address instead of domain name');
      }

      return {
        url: url,
        domain: domain,
        riskLevel: risks.length === 0 ? 'low' : risks.length === 1 ? 'medium' : 'high',
        risks: risks,
        recommendation: risks.length > 0 ? 'Be cautious when entering credentials on this site' : 'No obvious phishing indicators detected'
      };
    } catch (error) {
      return {
        url: url,
        riskLevel: 'unknown',
        risks: ['Could not analyze URL'],
        recommendation: 'Unable to assess phishing risk'
      };
    }
  }

  // Generate contextual password suggestions
  generatePasswordSuggestion(context = {}) {
    const { domain, username, requirements = {} } = context;
    
    // Determine password length based on requirements
    const length = requirements.minLength ? Math.max(20, requirements.minLength) : 20;
    
    // Generate base password
    let password = passwordManager.generatePassword(length, {
      includeUppercase: requirements.requireUppercase !== false,
      includeLowercase: requirements.requireLowercase !== false,
      includeNumbers: requirements.requireNumbers !== false,
      includeSymbols: requirements.requireSymbols !== false
    });

    // Ensure password meets specific requirements
    if (requirements.requireUppercase && !/[A-Z]/.test(password)) {
      password = password.slice(0, -1) + 'A';
    }
    if (requirements.requireLowercase && !/[a-z]/.test(password)) {
      password = password.slice(0, -1) + 'a';
    }
    if (requirements.requireNumbers && !/[0-9]/.test(password)) {
      password = password.slice(0, -1) + '1';
    }
    if (requirements.requireSymbols && !/[^a-zA-Z0-9]/.test(password)) {
      password = password.slice(0, -1) + '!';
    }

    return {
      password: password,
      strength: passwordManager.checkPasswordStrength(password),
      memorable: this.generateMemorablePassword()
    };
  }

  // Generate memorable password using word combinations
  generateMemorablePassword() {
    const adjectives = ['Swift', 'Bright', 'Silent', 'Golden', 'Crystal', 'Frozen', 'Ancient', 'Mystic'];
    const nouns = ['Phoenix', 'Thunder', 'Ocean', 'Mountain', 'Forest', 'Dragon', 'Falcon', 'Tiger'];
    const symbols = ['!', '@', '#', '$', '%', '&', '*'];
    
    const adjective = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    const number = Math.floor(Math.random() * 9000) + 1000;
    const symbol = symbols[Math.floor(Math.random() * symbols.length)];
    
    return `${adjective}${noun}${number}${symbol}`;
  }

  // Automatic login capability
  async performAutoLogin(tabId, credentialId) {
    try {
      // First, auto-fill the credentials
      const fillResult = await this.autoFillCredentials(tabId, credentialId);
      
      if (!fillResult.success) {
        return fillResult;
      }

      // Then submit the form
      const submitResult = await chrome.scripting.executeScript({
        target: { tabId },
        func: this.submitLoginForm
      });

      return {
        success: true,
        submitted: submitResult[0]?.result || false
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Function to submit login form
  submitLoginForm() {
    // Find the filled password field
    const passwordField = document.querySelector('input[type="password"][value]:not([value=""])');
    
    if (!passwordField) {
      return false;
    }

    // Find the form
    const form = passwordField.closest('form');
    
    if (form) {
      // Look for submit button
      const submitButton = form.querySelector(
        'button[type="submit"], input[type="submit"], button:not([type="button"])'
      );
      
      if (submitButton) {
        submitButton.click();
        return true;
      }
      
      // Try to submit form directly
      form.submit();
      return true;
    }

    // Look for nearby submit button
    const nearbyButton = passwordField.parentElement?.querySelector(
      'button, input[type="submit"]'
    ) || document.querySelector('button[type="submit"]');
    
    if (nearbyButton) {
      nearbyButton.click();
      return true;
    }

    return false;
  }
}

// Export singleton instance
const aiPasswordAgent = new AIPasswordAgent();
export default aiPasswordAgent;