// Password Manager Integration for Side Panel

// This script integrates the password manager into the existing side panel
// It should be included in the sidepanel.html or sidepanel.js

// Initialize password manager when side panel loads
document.addEventListener('DOMContentLoaded', () => {
  // Check if we're in the side panel context
  if (window.location.pathname.includes('sidepanel.html')) {
    initializePasswordManager();
  }
});

// Initialize the password manager UI
async function initializePasswordManager() {
  // Create a container for the password manager
  const passwordManagerContainer = document.createElement('div');
  passwordManagerContainer.id = 'password-manager-container';
  passwordManagerContainer.style.display = 'none'; // Hidden by default
  
  // Add to the root element or create a tab for it
  const rootElement = document.getElementById('root');
  if (rootElement) {
    // Check if there's a tab system
    const tabContainer = rootElement.querySelector('.tab-container') || createTabSystem(rootElement);
    
    // Add password manager tab
    addPasswordManagerTab(tabContainer, passwordManagerContainer);
  }
  
  // Load password manager styles
  loadPasswordManagerStyles();
  
  // Initialize React component when needed
  window.initPasswordManager = () => {
    if (window.React && window.ReactDOM) {
      // Import and render the password manager component
      import('./passwordManagerUI.jsx').then(({ PasswordManagerPanel }) => {
        ReactDOM.render(
          React.createElement(PasswordManagerPanel),
          passwordManagerContainer
        );
      });
    } else {
      console.error('React not available for password manager');
    }
  };
}

// Create a simple tab system if none exists
function createTabSystem(rootElement) {
  const tabSystem = document.createElement('div');
  tabSystem.className = 'tab-system';
  
  const tabHeader = document.createElement('div');
  tabHeader.className = 'tab-header';
  tabHeader.style.cssText = `
    display: flex;
    border-bottom: 1px solid #3a3a3a;
    background: #2a2a2a;
    padding: 0 8px;
  `;
  
  const tabContent = document.createElement('div');
  tabContent.className = 'tab-content';
  tabContent.style.cssText = `
    flex: 1;
    overflow: hidden;
    position: relative;
  `;
  
  tabSystem.appendChild(tabHeader);
  tabSystem.appendChild(tabContent);
  
  // Move existing content to a tab
  const existingContent = document.createElement('div');
  existingContent.className = 'tab-pane active';
  existingContent.id = 'ai-chat-tab';
  while (rootElement.firstChild) {
    existingContent.appendChild(rootElement.firstChild);
  }
  
  // Add tab button for existing content
  const aiChatTab = createTabButton('AI Chat', 'ai-chat-tab', true);
  tabHeader.appendChild(aiChatTab);
  tabContent.appendChild(existingContent);
  
  rootElement.appendChild(tabSystem);
  
  return { header: tabHeader, content: tabContent };
}

// Add password manager tab
function addPasswordManagerTab(tabContainer, passwordManagerContainer) {
  const { header, content } = tabContainer;
  
  // Create tab button
  const passwordTab = createTabButton('🔐 Passwords', 'password-manager-tab', false);
  header.appendChild(passwordTab);
  
  // Create tab pane
  const passwordPane = document.createElement('div');
  passwordPane.className = 'tab-pane';
  passwordPane.id = 'password-manager-tab';
  passwordPane.style.cssText = `
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    display: none;
    overflow: hidden;
  `;
  passwordPane.appendChild(passwordManagerContainer);
  content.appendChild(passwordPane);
  
  // Handle tab switching
  passwordTab.addEventListener('click', () => {
    // Hide all panes
    content.querySelectorAll('.tab-pane').forEach(pane => {
      pane.style.display = 'none';
      pane.classList.remove('active');
    });
    
    // Deactivate all tabs
    header.querySelectorAll('.tab-button').forEach(btn => {
      btn.classList.remove('active');
    });
    
    // Show password manager
    passwordPane.style.display = 'block';
    passwordPane.classList.add('active');
    passwordTab.classList.add('active');
    passwordManagerContainer.style.display = 'block';
    
    // Initialize password manager if not already done
    if (!passwordManagerContainer.hasChildNodes() && window.initPasswordManager) {
      window.initPasswordManager();
    }
  });
}

// Create a tab button
function createTabButton(label, targetId, isActive) {
  const button = document.createElement('button');
  button.className = `tab-button ${isActive ? 'active' : ''}`;
  button.textContent = label;
  button.dataset.target = targetId;
  button.style.cssText = `
    background: transparent;
    border: none;
    color: ${isActive ? '#4a9eff' : '#888'};
    padding: 12px 16px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    transition: all 0.2s;
    border-bottom: 2px solid ${isActive ? '#4a9eff' : 'transparent'};
  `;
  
  button.addEventListener('mouseenter', () => {
    if (!button.classList.contains('active')) {
      button.style.color = '#ccc';
    }
  });
  
  button.addEventListener('mouseleave', () => {
    if (!button.classList.contains('active')) {
      button.style.color = '#888';
    }
  });
  
  return button;
}

// Load password manager styles
function loadPasswordManagerStyles() {
  if (!document.getElementById('password-manager-styles')) {
    const link = document.createElement('link');
    link.id = 'password-manager-styles';
    link.rel = 'stylesheet';
    link.href = 'passwordManager.css';
    document.head.appendChild(link);
  }
}

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'openPasswordManager') {
    // Switch to password manager tab
    const passwordTab = document.querySelector('[data-target="password-manager-tab"]');
    if (passwordTab) {
      passwordTab.click();
    }
  }
});

// Export for use in other scripts
window.passwordManagerIntegration = {
  initialize: initializePasswordManager,
  show: () => {
    const passwordTab = document.querySelector('[data-target="password-manager-tab"]');
    if (passwordTab) {
      passwordTab.click();
    }
  }
};