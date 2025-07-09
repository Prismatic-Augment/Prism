// TOTP (Time-based One-Time Password) Manager for 2FA Support

class TOTPManager {
  constructor() {
    this.hotp = this.hotp.bind(this);
  }

  // Convert base32 to hex
  base32ToHex(base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let hex = '';

    // Remove spaces and convert to uppercase
    base32 = base32.replace(/\s/g, '').toUpperCase();

    // Convert each character to 5-bit binary
    for (let i = 0; i < base32.length; i++) {
      const val = base32Chars.indexOf(base32.charAt(i));
      if (val === -1) throw new Error('Invalid base32 character');
      bits += val.toString(2).padStart(5, '0');
    }

    // Convert binary to hex
    for (let i = 0; i < bits.length - 3; i += 4) {
      const chunk = bits.substr(i, 4);
      hex += parseInt(chunk, 2).toString(16);
    }

    return hex;
  }

  // HMAC-SHA1 implementation
  async hmacSha1(key, message) {
    const encoder = new TextEncoder();
    const keyData = this.hexToUint8Array(key);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      this.hexToUint8Array(message)
    );

    return this.uint8ArrayToHex(new Uint8Array(signature));
  }

  // Convert hex string to Uint8Array
  hexToUint8Array(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
  }

  // Convert Uint8Array to hex string
  uint8ArrayToHex(array) {
    return Array.from(array)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // HOTP (HMAC-based One-Time Password) algorithm
  async hotp(key, counter, digits = 6) {
    // Convert counter to 8-byte hex string
    const counterHex = counter.toString(16).padStart(16, '0');
    
    // Calculate HMAC
    const hmac = await this.hmacSha1(key, counterHex);
    
    // Dynamic truncation
    const offset = parseInt(hmac.substr(hmac.length - 1), 16);
    const truncated = hmac.substr(offset * 2, 8);
    
    // Convert to number and apply modulo
    let otp = parseInt(truncated, 16) & 0x7fffffff;
    otp = otp % Math.pow(10, digits);
    
    // Pad with zeros if needed
    return otp.toString().padStart(digits, '0');
  }

  // TOTP (Time-based One-Time Password) algorithm
  async generateTOTP(secret, options = {}) {
    const {
      period = 30,
      digits = 6,
      timestamp = Date.now(),
      algorithm = 'SHA1'
    } = options;

    // Convert base32 secret to hex
    const keyHex = this.base32ToHex(secret);
    
    // Calculate time counter
    const counter = Math.floor(timestamp / 1000 / period);
    
    // Generate HOTP
    return this.hotp(keyHex, counter, digits);
  }

  // Get remaining time for current TOTP
  getTimeRemaining(period = 30) {
    const now = Date.now();
    const currentPeriod = Math.floor(now / 1000 / period);
    const nextPeriod = (currentPeriod + 1) * period * 1000;
    return Math.ceil((nextPeriod - now) / 1000);
  }

  // Generate QR code data for TOTP
  generateTOTPUri(label, secret, options = {}) {
    const {
      issuer = 'BrowserOS Password Manager',
      digits = 6,
      period = 30,
      algorithm = 'SHA1'
    } = options;

    const params = new URLSearchParams({
      secret: secret,
      issuer: issuer,
      digits: digits.toString(),
      period: period.toString(),
      algorithm: algorithm
    });

    return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
  }

  // Parse TOTP URI
  parseTOTPUri(uri) {
    const match = uri.match(/^otpauth:\/\/totp\/([^?]+)\?(.+)$/);
    if (!match) throw new Error('Invalid TOTP URI');

    const label = decodeURIComponent(match[1]);
    const params = new URLSearchParams(match[2]);

    return {
      label,
      secret: params.get('secret'),
      issuer: params.get('issuer'),
      digits: parseInt(params.get('digits') || '6'),
      period: parseInt(params.get('period') || '30'),
      algorithm: params.get('algorithm') || 'SHA1'
    };
  }

  // Verify TOTP code
  async verifyTOTP(secret, code, options = {}) {
    const {
      window = 1, // Allow 1 period before/after
      period = 30,
      digits = 6
    } = options;

    const currentTime = Date.now();
    
    // Check current period and window periods
    for (let i = -window; i <= window; i++) {
      const testTime = currentTime + (i * period * 1000);
      const expectedCode = await this.generateTOTP(secret, {
        ...options,
        timestamp: testTime
      });
      
      if (expectedCode === code) {
        return {
          valid: true,
          delta: i
        };
      }
    }

    return {
      valid: false,
      delta: null
    };
  }

  // Backup codes generator
  generateBackupCodes(count = 10, length = 8) {
    const codes = [];
    const charset = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Exclude similar characters
    
    for (let i = 0; i < count; i++) {
      let code = '';
      const randomBytes = crypto.getRandomValues(new Uint8Array(length));
      
      for (let j = 0; j < length; j++) {
        code += charset[randomBytes[j] % charset.length];
        if (j === 3) code += '-'; // Add hyphen for readability
      }
      
      codes.push(code);
    }
    
    return codes;
  }
}

// Enhanced Password Manager with TOTP support
class EnhancedCredential {
  constructor(credential) {
    this.credential = credential;
  }

  // Add TOTP to credential
  async addTOTP(secret, options = {}) {
    const totp = {
      secret,
      issuer: options.issuer || new URL(this.credential.domain).hostname,
      digits: options.digits || 6,
      period: options.period || 30,
      algorithm: options.algorithm || 'SHA1',
      backupCodes: options.backupCodes || []
    };

    this.credential.totp = totp;
    return this.credential;
  }

  // Get current TOTP code
  async getCurrentTOTP() {
    if (!this.credential.totp) return null;
    
    const totpManager = new TOTPManager();
    const code = await totpManager.generateTOTP(this.credential.totp.secret, {
      digits: this.credential.totp.digits,
      period: this.credential.totp.period,
      algorithm: this.credential.totp.algorithm
    });

    const timeRemaining = totpManager.getTimeRemaining(this.credential.totp.period);

    return {
      code,
      timeRemaining,
      period: this.credential.totp.period
    };
  }

  // Auto-fill TOTP code
  async autoFillTOTP(tabId) {
    const totpData = await this.getCurrentTOTP();
    if (!totpData) return { success: false, error: 'No TOTP configured' };

    // Inject code to find and fill TOTP field
    const result = await chrome.scripting.executeScript({
      target: { tabId },
      func: (code) => {
        // Common selectors for TOTP fields
        const selectors = [
          'input[name*="totp"]',
          'input[name*="2fa"]',
          'input[name*="twofa"]',
          'input[name*="code"]',
          'input[name*="token"]',
          'input[name*="otp"]',
          'input[placeholder*="code"]',
          'input[placeholder*="2fa"]',
          'input[type="number"][maxlength="6"]',
          'input[type="text"][maxlength="6"]'
        ];

        for (const selector of selectors) {
          const field = document.querySelector(selector);
          if (field && field.offsetParent !== null) {
            field.value = code;
            field.dispatchEvent(new Event('input', { bubbles: true }));
            field.dispatchEvent(new Event('change', { bubbles: true }));
            
            // Auto-submit if there's a submit button
            const form = field.closest('form');
            if (form) {
              const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
              if (submitButton) {
                setTimeout(() => submitButton.click(), 100);
              }
            }
            
            return true;
          }
        }
        
        return false;
      },
      args: [totpData.code]
    });

    return {
      success: result[0]?.result || false,
      code: totpData.code,
      timeRemaining: totpData.timeRemaining
    };
  }
}

// Export modules
const totpManager = new TOTPManager();
export { totpManager, TOTPManager, EnhancedCredential };