// Password Manager Background Script
import passwordManager from './passwordManager.js';
import aiPasswordAgent from './aiPasswordAgent.js';

// Message handler for password manager operations
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  (async () => {
    try {
      switch (request.action) {
        case 'unlock':
          const unlocked = await passwordManager.unlock(request.masterPassword);
          sendResponse({ success: unlocked });
          break;

        case 'lock':
          passwordManager.lock();
          sendResponse({ success: true });
          break;

        case 'isUnlocked':
          sendResponse({ isUnlocked: passwordManager.isUnlocked });
          break;

        case 'saveCredential':
          await passwordManager.saveCredential(request.credential);
          sendResponse({ success: true });
          break;

        case 'getCredentials':
          const credentials = await passwordManager.getAllCredentials();
          sendResponse({ credentials });
          break;

        case 'getCredentialsForDomain':
          const domainCreds = await passwordManager.getCredentialsForDomain(request.domain);
          sendResponse({ credentials: domainCreds });
          break;

        case 'deleteCredential':
          await passwordManager.deleteCredential(request.id);
          sendResponse({ success: true });
          break;

        case 'generatePassword':
          const password = passwordManager.generatePassword(request.length, request.options);
          sendResponse({ password });
          break;

        case 'checkPasswordStrength':
          const strength = passwordManager.checkPasswordStrength(request.password);
          sendResponse({ strength });
          break;

        case 'detectLoginForms':
          const forms = await aiPasswordAgent.detectLoginForms(request.tabId);
          sendResponse({ forms });
          break;

        case 'autoFillCredentials':
          const fillResult = await aiPasswordAgent.autoFillCredentials(request.tabId, request.credentialId);
          sendResponse(fillResult);
          break;

        case 'performAutoLogin':
          const loginResult = await aiPasswordAgent.performAutoLogin(request.tabId, request.credentialId);
          sendResponse(loginResult);
          break;

        case 'analyzePasswordSecurity':
          const analysis = await aiPasswordAgent.analyzePasswordSecurity(request.password);
          sendResponse({ analysis });
          break;

        case 'checkPhishingRisk':
          const risk = await aiPasswordAgent.checkPhishingRisk(request.url);
          sendResponse({ risk });
          break;

        case 'exportCredentials':
          const exportData = await passwordManager.exportCredentials();
          sendResponse({ data: exportData });
          break;

        case 'importCredentials':
          const count = await passwordManager.importCredentials(request.data, request.masterPassword);
          sendResponse({ count });
          break;

        default:
          sendResponse({ error: 'Unknown action' });
      }
    } catch (error) {
      console.error('Background script error:', error);
      sendResponse({ error: error.message });
    }
  })();
  
  // Return true to indicate async response
  return true;
});

// Listen for tab updates to detect login pages
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    try {
      // Check if it's a potential login page
      const forms = await aiPasswordAgent.detectLoginForms(tabId);
      
      if (forms.length > 0) {
        // Check for saved credentials
        const credentials = await passwordManager.getCredentialsForDomain(tab.url);
        
        if (credentials.length > 0) {
          // Show notification that credentials are available
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'assets/icon128.png',
            title: 'Saved Credentials Available',
            message: `${credentials.length} saved credential(s) for this site`,
            buttons: [{ title: 'Auto-fill' }],
            priority: 2
          });
        }

        // Check phishing risk
        const risk = await aiPasswordAgent.checkPhishingRisk(tab.url);
        if (risk.riskLevel === 'high') {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'assets/icon128.png',
            title: 'Security Warning',
            message: risk.recommendation,
            priority: 2
          });
        }
      }
    } catch (error) {
      console.error('Tab update error:', error);
    }
  }
});

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  if (buttonIndex === 0) {
    // Auto-fill button clicked
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      const credentials = await passwordManager.getCredentialsForDomain(tab.url);
      if (credentials.length > 0) {
        // Auto-fill with the most recent credential
        await aiPasswordAgent.autoFillCredentials(tab.id, credentials[0].id);
      }
    }
  }
});

// Context menu for password generation
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'generatePassword',
    title: 'Generate Secure Password',
    contexts: ['editable']
  });

  chrome.contextMenus.create({
    id: 'savePassword',
    title: 'Save Password',
    contexts: ['password']
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'generatePassword') {
    const password = passwordManager.generatePassword();
    
    // Insert the password into the focused field
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (password) => {
        const activeElement = document.activeElement;
        if (activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA')) {
          activeElement.value = password;
          activeElement.dispatchEvent(new Event('input', { bubbles: true }));
          activeElement.dispatchEvent(new Event('change', { bubbles: true }));
        }
      },
      args: [password]
    });

    // Show notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'assets/icon128.png',
      title: 'Password Generated',
      message: 'A secure password has been generated and inserted'
    });
  } else if (info.menuItemId === 'savePassword') {
    // Open side panel to save the password
    chrome.sidePanel.open({ tabId: tab.id });
  }
});

// Monitor form submissions to offer to save credentials
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.transitionType === 'form_submit' && details.frameId === 0) {
    // Inject script to capture form data
    try {
      await chrome.scripting.executeScript({
        target: { tabId: details.tabId },
        func: captureFormData,
        world: 'MAIN'
      });
    } catch (error) {
      console.error('Failed to capture form data:', error);
    }
  }
});

// Function to capture form data (injected into page)
function captureFormData() {
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const passwordField = form.querySelector('input[type="password"]');
    if (passwordField && passwordField.value) {
      const usernameField = form.querySelector('input[type="text"], input[type="email"]');
      
      if (usernameField && usernameField.value) {
        // Send data to extension
        window.postMessage({
          type: 'SAVE_CREDENTIAL_OFFER',
          data: {
            domain: window.location.href,
            username: usernameField.value,
            password: passwordField.value
          }
        }, '*');
      }
    }
  });
}

// Listen for messages from injected scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SAVE_CREDENTIAL_OFFER' && message.data) {
    // Show notification to save credentials
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'assets/icon128.png',
      title: 'Save Password?',
      message: `Save password for ${message.data.username}?`,
      buttons: [
        { title: 'Save' },
        { title: 'Never' }
      ],
      priority: 2
    });

    // Store the credential data temporarily
    chrome.storage.session.set({
      pendingCredential: message.data
    });
  }
});

// Auto-lock timer
let lockTimer = null;

const resetLockTimer = () => {
  if (lockTimer) {
    clearTimeout(lockTimer);
  }
  
  // Get lock timeout from settings (default 5 minutes)
  chrome.storage.local.get('autoLockMinutes', (data) => {
    const minutes = data.autoLockMinutes || 5;
    lockTimer = setTimeout(() => {
      passwordManager.lock();
      // Notify all tabs that the password manager is locked
      chrome.runtime.sendMessage({ type: 'PASSWORD_MANAGER_LOCKED' });
    }, minutes * 60 * 1000);
  });
};

// Reset timer on any activity
chrome.runtime.onMessage.addListener((message) => {
  if (passwordManager.isUnlocked) {
    resetLockTimer();
  }
});

// Export for use in other scripts
export { passwordManager, aiPasswordAgent };