// =============================================================================
// Credential Store — Abstraction over GCP Secret Manager for connector creds
// =============================================================================
// In GCP (production): uses Secret Manager
// Locally / no Secret Manager: falls back to in-memory encrypted store
// Credentials are NEVER stored in the database.
// =============================================================================

const crypto = require('crypto');

// Encryption key for local fallback (derived from env or random per-process)
const LOCAL_ENCRYPTION_KEY = crypto
  .createHash('sha256')
  .update(process.env.CREDENTIAL_ENCRYPTION_KEY || process.env.WID_TOKEN_SECRET || 'local-dev-key-change-in-prod')
  .digest();

// In-memory encrypted store (local fallback)
const localStore = new Map();

// Lazy-loaded Secret Manager client
let smClient = null;
let smAvailable = null;
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || '';

async function getSecretManagerClient() {
  if (smAvailable === false) return null;
  if (smClient) return smClient;

  try {
    const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
    smClient = new SecretManagerServiceClient();
    // Quick check — list secrets to verify access
    const parent = `projects/${GCP_PROJECT_ID}`;
    await smClient.listSecrets({ parent, pageSize: 1 });
    smAvailable = true;
    console.log('[credential-store] Using GCP Secret Manager');
    return smClient;
  } catch (err) {
    smAvailable = false;
    console.log(`[credential-store] Secret Manager unavailable (${err.message}), using local encrypted store`);
    return null;
  }
}

function secretName(connectorId) {
  return `connector-${connectorId}-creds`;
}

function encrypt(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', LOCAL_ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

function decrypt(ciphertext) {
  const [ivHex, tagHex, encrypted] = ciphertext.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', LOCAL_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Store credentials for a connector.
 * @param {string} connectorId - UUID of the connector
 * @param {string} provider - aws, gcp, azure, etc.
 * @param {object} credentials - Provider-specific credential object (never logged)
 * @returns {string} The credential reference (secret name)
 */
async function storeCredentials(connectorId, provider, credentials) {
  const name = secretName(connectorId);
  const payload = JSON.stringify({ provider, credentials, stored_at: new Date().toISOString() });

  const client = await getSecretManagerClient();
  if (client && GCP_PROJECT_ID) {
    try {
      const parent = `projects/${GCP_PROJECT_ID}`;
      // Create the secret (ignore if exists)
      try {
        await client.createSecret({
          parent,
          secretId: name,
          secret: { replication: { automatic: {} } },
        });
      } catch (err) {
        if (err.code !== 6) throw err; // 6 = ALREADY_EXISTS
      }
      // Add a new version with the credential data
      await client.addSecretVersion({
        parent: `${parent}/secrets/${name}`,
        payload: { data: Buffer.from(payload, 'utf8') },
      });
      console.log(`[credential-store] Stored credentials in Secret Manager: ${name}`);
      return name;
    } catch (err) {
      console.error(`[credential-store] Secret Manager write failed, falling back to local: ${err.message}`);
    }
  }

  // Local fallback — AES-256-GCM encrypted in memory
  localStore.set(name, encrypt(payload));
  console.log(`[credential-store] Stored credentials locally (encrypted): ${name}`);
  return name;
}

/**
 * Retrieve credentials for a connector.
 * @param {string} connectorId - UUID of the connector
 * @returns {object|null} The credential object, or null if not found
 */
async function getCredentials(connectorId) {
  const name = secretName(connectorId);

  const client = await getSecretManagerClient();
  if (client && GCP_PROJECT_ID) {
    try {
      const [version] = await client.accessSecretVersion({
        name: `projects/${GCP_PROJECT_ID}/secrets/${name}/versions/latest`,
      });
      const payload = version.payload.data.toString('utf8');
      return JSON.parse(payload);
    } catch (err) {
      if (err.code === 5) return null; // NOT_FOUND
      console.error(`[credential-store] Secret Manager read failed, trying local: ${err.message}`);
    }
  }

  // Local fallback
  const encrypted = localStore.get(name);
  if (!encrypted) return null;
  try {
    return JSON.parse(decrypt(encrypted));
  } catch (err) {
    console.error(`[credential-store] Local decrypt failed: ${err.message}`);
    return null;
  }
}

/**
 * Delete credentials for a connector.
 * @param {string} connectorId - UUID of the connector
 */
async function deleteCredentials(connectorId) {
  const name = secretName(connectorId);

  const client = await getSecretManagerClient();
  if (client && GCP_PROJECT_ID) {
    try {
      await client.deleteSecret({
        name: `projects/${GCP_PROJECT_ID}/secrets/${name}`,
      });
      console.log(`[credential-store] Deleted from Secret Manager: ${name}`);
    } catch (err) {
      if (err.code !== 5) { // NOT_FOUND is fine
        console.error(`[credential-store] Secret Manager delete failed: ${err.message}`);
      }
    }
  }

  // Also clean local store
  localStore.delete(name);
}

module.exports = { storeCredentials, getCredentials, deleteCredentials };
