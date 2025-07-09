// Password Manager Content Script

// Track password fields on the page
let passwordFields = [];
let lastFocusedField = null;

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

function init() {
  // Scan for password fields
  scanForPasswordFields();
  
  // Set up mutation observer for dynamic content
  observeDOMChanges();
  
  // Listen for focus events on input fields
  document.addEventListener('focusin', handleFocusIn, true);
  
  // Listen for form submissions
  document.addEventListener('submit', handleFormSubmit, true);
  
  // Listen for messages from extension
  chrome.runtime.onMessage.addListener(handleMessage);
  
  // Listen for postMessage from injected scripts
  window.addEventListener('message', handleWindowMessage);
}

// Scan the page for password fields
function scanForPasswordFields() {
  passwordFields = [];
  const fields = document.querySelectorAll('input[type="password"]');
  
  fields.forEach(field => {
    if (!field.hasAttribute('data-password-manager')) {
      field.setAttribute('data-password-manager', 'true');
      passwordFields.push(field);
      
      // Add visual indicator for enhanced fields
      addPasswordManagerIndicator(field);
    }
  });
  
  // Notify background script about detected forms
  if (passwordFields.length > 0) {
    chrome.runtime.sendMessage({
      type: 'PASSWORD_FIELDS_DETECTED',
      count: passwordFields.length,
      url: window.location.href
    });
  }
}

// Add visual indicator to password fields
function addPasswordManagerIndicator(field) {
  // Create indicator element
  const indicator = document.createElement('div');
  indicator.className = 'password-manager-indicator';
  indicator.innerHTML = '🔐';
  indicator.title = 'Password manager available';
  
  // Style the indicator
  indicator.style.cssText = `
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    cursor: pointer;
    font-size: 16px;
    z-index: 1000;
    user-select: none;
    pointer-events: auto;
  `;
  
  // Position relative to the field
  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';
  wrapper.style.width = getComputedStyle(field).width;
  
  field.parentNode.insertBefore(wrapper, field);
  wrapper.appendChild(field);
  wrapper.appendChild(indicator);
  
  // Handle click on indicator
  indicator.addEventListener('click', (e) => {
    e.stopPropagation();
    showPasswordOptions(field);
  });
}

// Show password options menu
function showPasswordOptions(field) {
  // Remove existing menu if any
  const existingMenu = document.querySelector('.password-manager-menu');
  if (existingMenu) {
    existingMenu.remove();
  }
  
  // Create options menu
  const menu = document.createElement('div');
  menu.className = 'password-manager-menu';
  menu.innerHTML = `
    <div class="password-menu-item" data-action="autofill">
      <span class="menu-icon">⚡</span>
      <span>Auto-fill password</span>
    </div>
    <div class="password-menu-item" data-action="generate">
      <span class="menu-icon">🎲</span>
      <span>Generate password</span>
    </div>
    <div class="password-menu-item" data-action="save">
      <span class="menu-icon">💾</span>
      <span>Save current password</span>
    </div>
    <div class="password-menu-item" data-action="open">
      <span class="menu-icon">🔑</span>
      <span>Open password manager</span>
    </div>
  `;
  
  // Style the menu
  menu.style.cssText = `
    position: absolute;
    background: #2a2a2a;
    border: 1px solid #3a3a3a;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    padding: 4px;
    z-index: 10000;
    min-width: 200px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    color: #e4e4e4;
  `;
  
  // Style menu items
  const style = document.createElement('style');
  style.textContent = `
    .password-menu-item {
      display: flex;
      align-items: center;
      padding: 8px 12px;
      cursor: pointer;
      border-radius: 4px;
      transition: background 0.2s;
    }
    .password-menu-item:hover {
      background: rgba(74, 158, 255, 0.2);
    }
    .menu-icon {
      margin-right: 8px;
      font-size: 16px;
    }
  `;
  document.head.appendChild(style);
  
  // Position menu near the field
  const rect = field.getBoundingClientRect();
  menu.style.top = `${rect.bottom + window.scrollY + 4}px`;
  menu.style.left = `${rect.left + window.scrollX}px`;
  
  document.body.appendChild(menu);
  
  // Handle menu item clicks
  menu.addEventListener('click', async (e) => {
    const item = e.target.closest('.password-menu-item');
    if (!item) return;
    
    const action = item.dataset.action;
    menu.remove();
    
    switch (action) {
      case 'autofill':
        requestAutoFill(field);
        break;
      case 'generate':
        generatePassword(field);
        break;
      case 'save':
        saveCurrentPassword(field);
        break;
      case 'open':
        chrome.runtime.sendMessage({ action: 'openPasswordManager' });
        break;
    }
  });
  
  // Remove menu when clicking outside
  setTimeout(() => {
    document.addEventListener('click', function removeMenu(e) {
      if (!menu.contains(e.target)) {
        menu.remove();
        document.removeEventListener('click', removeMenu);
      }
    });
  }, 0);
}

// Request auto-fill for a field
async function requestAutoFill(passwordField) {
  // Find associated username field
  const form = passwordField.closest('form');
  const usernameField = findUsernameField(form || document);
  
  // Request credentials from background
  chrome.runtime.sendMessage({
    action: 'getCredentialsForDomain',
    domain: window.location.href
  }, response => {
    if (response.credentials && response.credentials.length > 0) {
      if (response.credentials.length === 1) {
        // Auto-fill single credential
        fillCredentials(usernameField, passwordField, response.credentials[0]);
      } else {
        // Show credential picker
        showCredentialPicker(usernameField, passwordField, response.credentials);
      }
    } else {
      showNotification('No saved passwords for this site');
    }
  });
}

// Find username field associated with password field
function findUsernameField(container) {
  const selectors = [
    'input[type="email"]',
    'input[type="text"][name*="user"]',
    'input[type="text"][name*="email"]',
    'input[type="text"][id*="user"]',
    'input[type="text"][id*="email"]',
    'input[type="text"][placeholder*="user"]',
    'input[type="text"][placeholder*="email"]',
    'input[type="text"]'
  ];
  
  for (const selector of selectors) {
    const field = container.querySelector(selector);
    if (field && field.offsetParent !== null) {
      return field;
    }
  }
  
  return null;
}

// Fill credentials into fields
function fillCredentials(usernameField, passwordField, credential) {
  chrome.runtime.sendMessage({
    action: 'autoFillCredentials',
    tabId: chrome.runtime.id,
    credentialId: credential.id
  }, response => {
    if (response.success) {
      showNotification('Credentials filled');
    }
  });
}

// Show credential picker for multiple options
function showCredentialPicker(usernameField, passwordField, credentials) {
  const picker = document.createElement('div');
  picker.className = 'password-credential-picker';
  
  const header = document.createElement('div');
  header.textContent = 'Select account:';
  header.style.cssText = 'padding: 12px; font-weight: 500; border-bottom: 1px solid #3a3a3a;';
  picker.appendChild(header);
  
  credentials.forEach(cred => {
    const item = document.createElement('div');
    item.className = 'credential-picker-item';
    item.innerHTML = `
      <div style="font-weight: 500;">${cred.username}</div>
      <div style="font-size: 12px; color: #888;">Last used: ${cred.lastUsed}</div>
    `;
    item.style.cssText = `
      padding: 12px;
      cursor: pointer;
      border-bottom: 1px solid #2a2a2a;
      transition: background 0.2s;
    `;
    
    item.addEventListener('mouseenter', () => {
      item.style.background = 'rgba(74, 158, 255, 0.1)';
    });
    
    item.addEventListener('mouseleave', () => {
      item.style.background = 'transparent';
    });
    
    item.addEventListener('click', () => {
      fillCredentials(usernameField, passwordField, cred);
      picker.remove();
    });
    
    picker.appendChild(item);
  });
  
  // Style the picker
  picker.style.cssText = `
    position: absolute;
    background: #252525;
    border: 1px solid #3a3a3a;
    border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    z-index: 10000;
    min-width: 250px;
    max-height: 300px;
    overflow-y: auto;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    color: #e4e4e4;
  `;
  
  // Position near password field
  const rect = passwordField.getBoundingClientRect();
  picker.style.top = `${rect.bottom + window.scrollY + 4}px`;
  picker.style.left = `${rect.left + window.scrollX}px`;
  
  document.body.appendChild(picker);
  
  // Remove picker when clicking outside
  setTimeout(() => {
    document.addEventListener('click', function removePicker(e) {
      if (!picker.contains(e.target)) {
        picker.remove();
        document.removeEventListener('click', removePicker);
      }
    });
  }, 0);
}

// Generate password for a field
function generatePassword(field) {
  chrome.runtime.sendMessage({
    action: 'generatePassword'
  }, response => {
    if (response.password) {
      field.value = response.password;
      field.dispatchEvent(new Event('input', { bubbles: true }));
      field.dispatchEvent(new Event('change', { bubbles: true }));
      
      // Show password strength
      chrome.runtime.sendMessage({
        action: 'checkPasswordStrength',
        password: response.password
      }, strengthResponse => {
        if (strengthResponse.strength) {
          showPasswordStrength(field, strengthResponse.strength);
        }
      });
      
      showNotification('Strong password generated');
    }
  });
}

// Show password strength indicator
function showPasswordStrength(field, strength) {
  // Remove existing strength indicator
  const existing = field.parentElement.querySelector('.password-strength-indicator');
  if (existing) existing.remove();
  
  const indicator = document.createElement('div');
  indicator.className = 'password-strength-indicator';
  indicator.innerHTML = `
    <div class="strength-bar">
      <div class="strength-fill strength-${strength.level}" style="width: ${strength.score}%"></div>
    </div>
    <span class="strength-text">Strength: ${strength.level}</span>
  `;
  
  // Style the indicator
  const style = document.createElement('style');
  style.textContent = `
    .password-strength-indicator {
      margin-top: 4px;
      font-size: 12px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .strength-bar {
      height: 4px;
      background: #e0e0e0;
      border-radius: 2px;
      overflow: hidden;
      margin-bottom: 2px;
    }
    .strength-fill {
      height: 100%;
      transition: width 0.3s;
    }
    .strength-fill.strength-weak { background: #ef4444; }
    .strength-fill.strength-fair { background: #f59e0b; }
    .strength-fill.strength-good { background: #10b981; }
    .strength-fill.strength-strong { background: #4a9eff; }
    .strength-text { color: #666; }
  `;
  
  if (!document.querySelector('#password-strength-styles')) {
    style.id = 'password-strength-styles';
    document.head.appendChild(style);
  }
  
  field.parentElement.appendChild(indicator);
}

// Save current password
function saveCurrentPassword(passwordField) {
  const form = passwordField.closest('form');
  const usernameField = findUsernameField(form || document);
  
  if (!passwordField.value) {
    showNotification('No password to save');
    return;
  }
  
  const credential = {
    domain: window.location.href,
    username: usernameField ? usernameField.value : '',
    password: passwordField.value
  };
  
  // Send to extension to save
  chrome.runtime.sendMessage({
    type: 'SAVE_CREDENTIAL_OFFER',
    data: credential
  });
}

// Handle focus on input fields
function handleFocusIn(e) {
  const field = e.target;
  
  if (field.type === 'password') {
    lastFocusedField = field;
    
    // Ensure field is tracked
    if (!field.hasAttribute('data-password-manager')) {
      field.setAttribute('data-password-manager', 'true');
      addPasswordManagerIndicator(field);
      passwordFields.push(field);
    }
    
    // Check for saved credentials
    checkForSavedCredentials(field);
  }
}

// Check for saved credentials when focusing a password field
function checkForSavedCredentials(field) {
  chrome.runtime.sendMessage({
    action: 'getCredentialsForDomain',
    domain: window.location.href
  }, response => {
    if (response.credentials && response.credentials.length > 0) {
      // Add subtle highlight to indicate saved credentials available
      field.style.borderColor = '#4a9eff';
      field.style.boxShadow = '0 0 0 1px #4a9eff';
    }
  });
}

// Handle form submissions
function handleFormSubmit(e) {
  const form = e.target;
  const passwordField = form.querySelector('input[type="password"]');
  
  if (passwordField && passwordField.value) {
    const usernameField = findUsernameField(form);
    
    if (usernameField && usernameField.value) {
      // Capture form data for potential saving
      const credential = {
        domain: window.location.href,
        username: usernameField.value,
        password: passwordField.value
      };
      
      // Store in session for post-submit handling
      sessionStorage.setItem('pendingCredential', JSON.stringify(credential));
    }
  }
}

// Handle messages from extension
function handleMessage(request, sender, sendResponse) {
  switch (request.action) {
    case 'fillCredentials':
      if (request.username && request.password) {
        const passwordFields = document.querySelectorAll('input[type="password"]:not([disabled])');
        const passwordField = passwordFields[0];
        
        if (passwordField) {
          const form = passwordField.closest('form');
          const usernameField = findUsernameField(form || document);
          
          if (usernameField) {
            usernameField.value = request.username;
            usernameField.dispatchEvent(new Event('input', { bubbles: true }));
            usernameField.dispatchEvent(new Event('change', { bubbles: true }));
          }
          
          passwordField.value = request.password;
          passwordField.dispatchEvent(new Event('input', { bubbles: true }));
          passwordField.dispatchEvent(new Event('change', { bubbles: true }));
          
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: 'No password field found' });
        }
      }
      break;
      
    case 'getFormData':
      const forms = Array.from(document.querySelectorAll('form')).map(form => {
        const passwordField = form.querySelector('input[type="password"]');
        const usernameField = findUsernameField(form);
        
        return {
          hasPassword: !!passwordField,
          hasUsername: !!usernameField,
          passwordValue: passwordField?.value || '',
          usernameValue: usernameField?.value || ''
        };
      });
      
      sendResponse({ forms });
      break;
  }
}

// Handle window messages (from injected scripts)
function handleWindowMessage(event) {
  if (event.data && event.data.type === 'SAVE_CREDENTIAL_OFFER') {
    // Forward to extension
    chrome.runtime.sendMessage(event.data);
  }
}

// Observe DOM changes for dynamically added forms
function observeDOMChanges() {
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === 1 && (
            node.matches('input[type="password"]') ||
            node.querySelector?.('input[type="password"]')
          )) {
            shouldScan = true;
            break;
          }
        }
      } else if (mutation.type === 'attributes' && 
                 mutation.target.matches('input') && 
                 mutation.attributeName === 'type') {
        shouldScan = true;
      }
      
      if (shouldScan) break;
    }
    
    if (shouldScan) {
      scanForPasswordFields();
    }
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type']
  });
}

// Show notification
function showNotification(message) {
  const notification = document.createElement('div');
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #2a2a2a;
    color: #e4e4e4;
    padding: 12px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    z-index: 10000;
    animation: slideIn 0.3s ease-out;
  `;
  
  // Add animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(100%); opacity: 0; }
    }
  `;
  
  if (!document.querySelector('#notification-animations')) {
    style.id = 'notification-animations';
    document.head.appendChild(style);
  }
  
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Check if there's a pending credential to save after navigation
if (sessionStorage.getItem('pendingCredential')) {
  const credential = JSON.parse(sessionStorage.getItem('pendingCredential'));
  sessionStorage.removeItem('pendingCredential');
  
  // Send to extension
  chrome.runtime.sendMessage({
    type: 'SAVE_CREDENTIAL_OFFER',
    data: credential
  });
}