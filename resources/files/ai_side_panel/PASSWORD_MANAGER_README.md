# Agentic Password Manager

A secure, AI-powered password manager integrated into the browser's side panel with advanced features for automated credential management.

## Features

### 🔐 Core Security
- **AES-256-GCM Encryption**: All credentials are encrypted locally using industry-standard encryption
- **PBKDF2 Key Derivation**: Master password is never stored, only used to derive encryption keys
- **Local Storage Only**: All data stays on your device - no cloud sync for maximum privacy
- **Auto-lock**: Automatically locks after 5 minutes of inactivity (configurable)
- **Secure Password Generation**: Generate strong, unique passwords with customizable options

### 🤖 AI Agent Capabilities
- **Smart Form Detection**: Automatically detects login forms on any website
- **Auto-fill**: One-click filling of saved credentials
- **Automatic Login**: AI agent can automatically submit login forms after filling
- **Phishing Detection**: Warns about suspicious login pages
- **Password Strength Analysis**: Real-time analysis of password strength
- **Breach Monitoring**: Checks if passwords have been compromised in known breaches
- **Smart Suggestions**: Context-aware password generation based on site requirements

### 💡 User Experience
- **Visual Indicators**: Password fields are enhanced with 🔐 icon for easy access
- **Context Menus**: Right-click to generate passwords or save credentials
- **Keyboard Shortcuts**: Ctrl+E (Cmd+E on Mac) to open password manager
- **Beautiful UI**: Modern, dark-themed interface that matches the browser
- **Import/Export**: Backup and restore your credentials

## Usage

### First Time Setup
1. Open the side panel (Ctrl+E or Cmd+E)
2. Navigate to the Password Manager tab
3. Create a strong master password
4. Start adding your credentials

### Adding Credentials
1. **Manual Entry**: Click "➕ Add" in the password manager
2. **Auto-capture**: When you log into a site, you'll be prompted to save
3. **Context Menu**: Right-click a password field and select "Save Password"

### Using Saved Credentials
1. **Click the 🔐 icon** on any password field
2. **Select "Auto-fill"** from the menu
3. Choose the account if multiple are saved
4. The AI will fill in your credentials

### Password Generation
1. Click the 🎲 icon on any password field
2. Or use the Generator tab in the password manager
3. Customize length and character requirements
4. Copy or auto-fill the generated password

### Security Features

#### Phishing Protection
The AI agent analyzes login pages for:
- Suspicious domain patterns
- Homograph attacks (lookalike characters)
- Excessive subdomains
- IP addresses instead of domains

#### Password Health Monitoring
- Real-time strength analysis
- Breach detection using Have I Been Pwned API (k-anonymity)
- Recommendations for improving weak passwords
- Alerts for compromised credentials

### Advanced Features

#### Automatic Login
Enable the AI agent to automatically:
1. Detect login forms
2. Fill in your credentials
3. Submit the form
4. Handle multi-step login processes

#### Smart Password Requirements
The AI understands common password requirements:
- Minimum/maximum length
- Required character types
- Special requirements (no repeated characters, etc.)

### Keyboard Shortcuts
- **Ctrl+E / Cmd+E**: Open password manager
- **Tab**: Navigate between fields
- **Enter**: Submit forms
- **Escape**: Close popups

### Backup & Restore

#### Export
1. Go to Settings tab
2. Click "Export Passwords"
3. Save the encrypted JSON file

#### Import
1. Go to Settings tab
2. Click "Import Passwords"
3. Select your backup file
4. Enter the master password used for that backup

## Privacy & Security

### What's Stored Locally
- Encrypted credentials
- Password salt
- Settings preferences
- Audit logs

### What's Never Stored
- Master password
- Decrypted credentials
- Browsing history (beyond login detection)

### Network Requests
- **Favicon API**: To show site icons
- **Have I Been Pwned**: Anonymous breach checking
- No telemetry or tracking

## Technical Details

### Encryption
```javascript
// AES-256-GCM with PBKDF2
{
  algorithm: 'AES-GCM',
  keyLength: 256,
  iterations: 100000,
  hash: 'SHA-256'
}
```

### Storage Structure
```javascript
{
  credentials: [{
    id: 'uuid',
    domain: 'https://example.com',
    username: 'visible',
    encrypted: {
      iv: [...],
      data: [...] // Contains password
    },
    lastModified: timestamp
  }],
  passwordSalt: [...],
  passwordVerifier: {...}
}
```

### API Integration
The password manager integrates with:
- Chrome Storage API (local)
- Chrome Tabs API (form detection)
- Chrome Scripting API (auto-fill)
- Chrome Notifications API (alerts)
- Web Crypto API (encryption)

## Troubleshooting

### Password Manager Won't Unlock
- Ensure you're using the correct master password
- Check if caps lock is on
- Try refreshing the browser

### Auto-fill Not Working
- Ensure the site is fully loaded
- Check if the password field is detected (🔐 icon)
- Try clicking directly on the password field first

### Can't Save Passwords
- Ensure password manager is unlocked
- Check if there's already a saved credential
- Verify the form has both username and password fields

## Future Enhancements
- Biometric authentication support
- Secure password sharing
- Password history tracking
- Custom field support
- Form fill profiles
- Secure notes storage