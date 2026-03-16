// =============================================================================
// Agent Card JWS Signer & Verifier — ES256 (ECDSA P-256)
// =============================================================================
//
// Zero-dependency module (uses Node.js crypto only).
// Produces JWS Compact Serialization (RFC 7515) for A2A Agent Cards.
//
// Usage:
//   const { signAgentCard, verifyAgentCard } = require('./agent-card-signer');
//   const jws = signAgentCard(cardObject, privateKeyPem, { kid: 'abc' });
//   const { valid, payload, error } = verifyAgentCard(jws, publicKeyPem);
// =============================================================================

'use strict';

const crypto = require('crypto');

/**
 * Base64url encode a buffer or string.
 * @param {Buffer|string} input
 * @returns {string}
 */
function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

/**
 * Base64url decode to buffer.
 * @param {string} str
 * @returns {Buffer}
 */
function base64urlDecode(str) {
  return Buffer.from(str, 'base64url');
}

/**
 * Sign an Agent Card object with ES256 (ECDSA P-256).
 *
 * @param {object} cardObject - The Agent Card JSON to sign
 * @param {string} privateKeyPem - PEM-encoded EC private key (P-256)
 * @param {object} [options]
 * @param {string} [options.kid] - Key ID for JWS header
 * @param {string} [options.iss] - Issuer claim
 * @param {number} [options.expiresInSeconds=2592000] - TTL in seconds (default 30 days)
 * @returns {string} JWS compact serialization (header.payload.signature)
 */
function signAgentCard(cardObject, privateKeyPem, options = {}) {
  const {
    kid = null,
    iss = null,
    expiresInSeconds = 30 * 24 * 60 * 60, // 30 days
  } = options;

  // JWS Header
  const header = {
    alg: 'ES256',
    typ: 'agent-card+jwt',
  };
  if (kid) header.kid = kid;

  // Payload: card + standard claims
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    ...cardObject,
    iat: now,
  };
  if (iss) payload.iss = iss;
  if (expiresInSeconds) payload.exp = now + expiresInSeconds;

  // Signing input: header.payload (both base64url encoded)
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  // ES256 signature using Node.js crypto
  const signer = crypto.createSign('SHA256');
  signer.update(signingInput);
  signer.end();

  // Sign returns DER-encoded signature; convert to IEEE P1363 (r||s) for JWS
  const derSig = signer.sign({ key: privateKeyPem, dsaEncoding: 'ieee-p1363' });
  const signatureB64 = base64url(derSig);

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

/**
 * Verify a JWS compact serialization of an Agent Card.
 *
 * @param {string} jws - JWS compact serialization string
 * @param {string} publicKeyPem - PEM-encoded EC public key (P-256)
 * @returns {{ valid: boolean, payload: object|null, header: object|null, error: string|null }}
 */
function verifyAgentCard(jws, publicKeyPem) {
  try {
    if (!jws || typeof jws !== 'string') {
      return { valid: false, payload: null, header: null, error: 'Invalid JWS format' };
    }

    const parts = jws.split('.');
    if (parts.length !== 3) {
      return { valid: false, payload: null, header: null, error: 'JWS must have 3 parts' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode and validate header
    const header = JSON.parse(base64urlDecode(headerB64).toString('utf8'));
    if (header.alg !== 'ES256') {
      return { valid: false, payload: null, header, error: `Unsupported algorithm: ${header.alg}` };
    }

    // Verify signature
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = base64urlDecode(signatureB64);

    const verifier = crypto.createVerify('SHA256');
    verifier.update(signingInput);
    verifier.end();

    const isValid = verifier.verify(
      { key: publicKeyPem, dsaEncoding: 'ieee-p1363' },
      signature
    );

    if (!isValid) {
      return { valid: false, payload: null, header, error: 'Signature verification failed' };
    }

    // Decode payload
    const payload = JSON.parse(base64urlDecode(payloadB64).toString('utf8'));

    // Check expiry
    if (payload.exp) {
      const now = Math.floor(Date.now() / 1000);
      if (now > payload.exp) {
        return { valid: false, payload, header, error: 'Signature expired' };
      }
    }

    return { valid: true, payload, header, error: null };
  } catch (err) {
    return { valid: false, payload: null, header: null, error: err.message };
  }
}

module.exports = { signAgentCard, verifyAgentCard };
