/**
 * Utility to mask and redact sensitive EUDI Wallet data (PII, cryptographic keys, tokens, nonces)
 * before rendering in the browser console or LogViewer component.
 */

// Regex patterns for sensitive wallet credentials
const JWT_REGEX = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*/g;
const REVOCATION_CODE_REGEX = /rev_bech32_[a-zA-Z0-9_-]+/g;
const BASE64_KEY_REGEX = /(?:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE|rwscd_wi_pubk|pubk|pubKey)[a-zA-Z0-9+/=_-]{16,}/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BEARER_TOKEN_REGEX = /(?:Bearer\s+|token[:=]\s*)[a-zA-Z0-9._-]{16,}/gi;
const PIN_PUBKEY_REGEX = /(?:wi_rwsca_pin_pubk|pinPubKey)[:=]\s*["']?([a-zA-Z0-9+/=_-]{8,})["']?/gi;
const UUID_FULL_REGEX = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;

/**
 * Mask a single string value according to sensitive credential patterns.
 */
export function maskString(text: string): string {
  if (!text || typeof text !== 'string') return text;

  let sanitized = text;

  // 1. Redact JWTs (Wallet Instance Attestations, challenge tokens, statuslist tokens)
  sanitized = sanitized.replace(JWT_REGEX, (jwt) => {
    const parts = jwt.split('.');
    const headerPrefix = parts[0] ? parts[0].substring(0, 10) : 'eyJ';
    return `${headerPrefix}...[REDACTED_JWT_SIGNATURE]`;
  });

  // 2. Redact Revocation Codes
  sanitized = sanitized.replace(REVOCATION_CODE_REGEX, (code) => {
    return `rev_bech32_[REDACTED_SECRET_${code.slice(-4)}]`;
  });

  // 3. Redact Cryptographic Key Materials
  sanitized = sanitized.replace(BASE64_KEY_REGEX, (key) => {
    return `[REDACTED_KEY_MATERIAL_${key.substring(0, 8)}...]`;
  });

  // 4. Redact Emails (PII)
  sanitized = sanitized.replace(EMAIL_REGEX, (email) => {
    const [name, domain] = email.split('@');
    const maskedName = name.length > 2 ? `${name[0]}***${name[name.length - 1]}` : '***';
    return `${maskedName}@${domain}`;
  });

  // 5. Redact Bearer / MPP / Challenge Tokens
  sanitized = sanitized.replace(BEARER_TOKEN_REGEX, (match) => {
    return `Bearer [REDACTED_AUTH_TOKEN]`;
  });

  // 6. Redact PIN Public Keys
  sanitized = sanitized.replace(PIN_PUBKEY_REGEX, () => {
    return `pin_key: [REDACTED_PIN_CREDENTIAL]`;
  });

  return sanitized;
}

/**
 * Recursively mask sensitive fields in objects/payloads.
 */
export function maskSensitiveObject(obj: any): any {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === 'string') {
    return maskString(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => maskSensitiveObject(item));
  }

  if (typeof obj === 'object') {
    const masked: Record<string, any> = {};
    const sensitiveFieldNames = [
      'pubKey',
      'pubk',
      'privateKey',
      'prvk',
      'revocationCode',
      'wpb_wi_revocation_code',
      'token',
      'mdvm_token',
      'rwsca_pin_session_token',
      'wpb_wia',
      'lstJwt',
      'wi_rwsca_pin_pubk',
      'pinPubKey',
      'mppToken',
      'mpp_registration_token',
      'authChallenge',
      'wpb_auth_challenge',
      'rwsca_auth_challenge',
      'mdvm_auth_challenge',
      'pns_auth_challenge',
      'rwscd_key_binding_signature',
      'signature'
    ];

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      const isSensitiveField = sensitiveFieldNames.some((s) => lowerKey.includes(s.toLowerCase()));

      if (isSensitiveField && typeof value === 'string') {
        if (value.startsWith('eyJ')) {
          masked[key] = `${value.substring(0, 10)}...[REDACTED_JWT]`;
        } else if (value.startsWith('rev_')) {
          masked[key] = `rev_[REDACTED_REVOCATION_CODE]`;
        } else {
          masked[key] = `[REDACTED_KEY: ${value.substring(0, 6)}***]`;
        }
      } else {
        masked[key] = maskSensitiveObject(value);
      }
    }
    return masked;
  }

  return obj;
}
