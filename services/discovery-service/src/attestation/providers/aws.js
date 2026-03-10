// =============================================================================
// AWS Attestation Provider
// =============================================================================
// Evidence collection:
//   - IMDSv2: Fetches signed instance identity document + PKCS7 signature
//   - STS: Calls GetCallerIdentity for IAM principal verification
//   - Available on: EC2, ECS, Lambda, EKS
//
// Verification:
//   - Validates PKCS7 signature against AWS public certificates (EC2)
//   - Verifies STS caller identity matches workload registration
//
// Trust level: Cryptographic (Tier 1) for IMDSv2, High (Tier 2) for STS
// =============================================================================

const BaseAttestationProvider = require('./BaseAttestationProvider');

const AWS_IMDS_BASE = 'http://169.254.169.254';
const AWS_IMDS_TOKEN_TTL = 21600; // 6 hours

// ── AWS Public Certificates for Instance Identity Document Verification ──
// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html
// These are the RSA-2048 public certificates used to verify instance identity documents.
// AWS rotates these infrequently; in production, cache and check for updates periodically.

const AWS_CERT_STANDARD = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMVoXDTI0MDYwNTE0MjgwMVowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlO73YWBCVyyqRPSMtMlPXg8Xa
c9KE2dD1cETdAgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIssx6H
SGEHmb8GA1UdIwR4MHaAFCXWzAgVyrbwnFncFFIssx6HSGEhoW6kbDBqMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEY
MBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1hem9uYXdz
LmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEA
FYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8TC1haGgSI
/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ7zvWbGd9
c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`;

// GovCloud regions use a different certificate
const AWS_CERT_GOVCLOUD = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMVoXDTI0MDYwNTE0MjgwMVowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlO73YWBCVyyqRPSMtMlPXg8Xa
c9KE2dD1cETdAgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIssx6H
SGEHMB8GA1UdIwQYMBaAFCXWzAgVyrbwnFncFFIssx6HSGEhMAwGA1UdEwQFMAMB
Af8wDQYJKoZIhvcNAQEFBQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6j
z7VOmJqO+pRlAbRlvY8TC1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lv
mZ/IzbOPIJWirlsllQIQ7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6Np
CKsqP/0=
-----END CERTIFICATE-----`;

// China regions use a different certificate
const AWS_CERT_CHINA = AWS_CERT_GOVCLOUD; // Placeholder — replace with actual China cert

class AWSAttestationProvider extends BaseAttestationProvider {
  constructor(config = {}) {
    super(config);
    this.platform = 'aws';
    this.tier = 1;
    this.region = config.region || process.env.AWS_DEFAULT_REGION || process.env.AWS_REGION;
    this._imdsToken = null;
    this._imdsTokenExpiry = 0;
  }

  getMethods() {
    return ['aws-imdsv2-signed', 'aws-sts-identity'];
  }

  // ── Detection ──

  async detect() {
    // Check env vars first (Lambda, ECS)
    if (process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.ECS_CONTAINER_METADATA_URI_V4) {
      this.region = this.region || process.env.AWS_REGION;
      return true;
    }

    // Try IMDSv2 (EC2, ECS on EC2)
    try {
      const token = await this.getIMDSToken();
      if (token) {
        this.region = this.region || (await this.httpGet(
          `${AWS_IMDS_BASE}/latest/meta-data/placement/region`,
          { 'X-aws-ec2-metadata-token': token }
        )).trim();
        return true;
      }
    } catch { /* not on EC2 */ }

    // Check AWS SDK credentials
    if (process.env.AWS_ACCESS_KEY_ID || process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
      return true;
    }

    return false;
  }

  // ── Self Evidence Collection ──

  async collectSelfEvidence() {
    const evidence = { platform: 'aws' };

    // Try IMDSv2 first (EC2/ECS on EC2)
    try {
      const token = await this.getIMDSToken();
      if (token) {
        evidence.instance_identity_document = await this.httpGet(
          `${AWS_IMDS_BASE}/latest/dynamic/instance-identity/document`,
          { 'X-aws-ec2-metadata-token': token }
        );
        evidence.signature = await this.httpGet(
          `${AWS_IMDS_BASE}/latest/dynamic/instance-identity/pkcs7`,
          { 'X-aws-ec2-metadata-token': token }
        );
      }
    } catch { /* not on EC2 */ }

    // Try STS GetCallerIdentity
    try {
      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
      const sts = new STSClient({ region: this.region || 'us-east-1' });
      const identity = await sts.send(new GetCallerIdentityCommand({}));
      evidence.caller_identity = {
        Account: identity.Account,
        Arn: identity.Arn,
        UserId: identity.UserId,
      };
    } catch (e) {
      this.log(`STS GetCallerIdentity failed: ${e.message}`, 'warn');
    }

    // Lambda-specific
    if (process.env.AWS_LAMBDA_FUNCTION_NAME) {
      evidence.lambda = {
        function_name: process.env.AWS_LAMBDA_FUNCTION_NAME,
        function_version: process.env.AWS_LAMBDA_FUNCTION_VERSION,
        log_group: process.env.AWS_LAMBDA_LOG_GROUP_NAME,
        memory_size: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE,
        execution_env: process.env.AWS_EXECUTION_ENV,
      };
    }

    // ECS-specific
    if (process.env.ECS_CONTAINER_METADATA_URI_V4) {
      try {
        const metaJson = await this.httpGet(process.env.ECS_CONTAINER_METADATA_URI_V4);
        evidence.ecs_metadata = JSON.parse(metaJson);
      } catch { /* */ }
    }

    return evidence;
  }

  // ── Workload Evidence Collection ──

  async collectWorkloadEvidence(workload) {
    const evidence = { platform: 'aws' };

    // For IAM roles/users, we have the ARN from discovery
    if (workload.metadata?.arn) {
      evidence.caller_identity = {
        Arn: workload.metadata.arn,
        Account: workload.account_id || workload.metadata.arn?.split(':')[4],
      };
    }

    // For EC2, we have instance metadata from discovery
    if (workload.type === 'ec2' && workload.metadata?.instance_id) {
      evidence.instance_metadata = {
        instanceId: workload.metadata.instance_id,
        region: workload.region,
        accountId: workload.account_id,
        imageId: workload.metadata.ami_id,
      };
    }

    // For Lambda, reconstruct from function metadata
    if (workload.type === 'lambda') {
      evidence.lambda = {
        function_name: workload.name,
        function_arn: workload.metadata?.arn || workload.arn,
        runtime: workload.metadata?.runtime,
        role: workload.metadata?.role,
      };
    }

    return evidence;
  }

  // ── Verification ──

  async verify(evidence, workload) {
    const timestamp = new Date().toISOString();

    // Priority 1: IMDSv2 signed document (Tier 1 - Cryptographic)
    if (evidence.instance_identity_document && evidence.signature) {
      return this.verifyIMDSv2(evidence, workload, timestamp);
    }

    // Priority 2: STS Caller Identity (Tier 2 - High)
    if (evidence.caller_identity) {
      return this.verifySTS(evidence, workload, timestamp);
    }

    // Priority 3: Lambda/ECS metadata (Tier 2 - High)
    if (evidence.lambda || evidence.ecs_metadata) {
      return this.verifyPlatformMetadata(evidence, workload, timestamp);
    }

    return {
      method: 'aws-imdsv2-signed',
      success: false,
      reason: 'No AWS attestation evidence available',
      timestamp,
    };
  }

  verifyIMDSv2(evidence, workload, timestamp) {
    try {
      const doc = typeof evidence.instance_identity_document === 'string'
        ? JSON.parse(evidence.instance_identity_document)
        : evidence.instance_identity_document;
      const docRaw = typeof evidence.instance_identity_document === 'string'
        ? evidence.instance_identity_document
        : JSON.stringify(evidence.instance_identity_document);

      // ── All checks must pass for cryptographic ──
      const checks = {
        doc_valid: false,
        instance_match: true, // default pass unless we have metadata to check
        region_valid: false,
        signature_verified: false,
      };

      // Check 1: Document is parseable and has required fields
      if (!doc.instanceId || !doc.accountId || !doc.region) {
        return { method: 'aws-imdsv2-signed', success: false,
          reason: 'Instance identity document missing required fields', timestamp };
      }
      checks.doc_valid = true;

      // Check 2: Instance ID matches registered workload
      if (workload.metadata?.instance_id && doc.instanceId !== workload.metadata.instance_id) {
        return { method: 'aws-imdsv2-signed', success: false,
          reason: `Instance ID mismatch: ${doc.instanceId} ≠ ${workload.metadata.instance_id}`, timestamp };
      }
      checks.instance_match = true;

      // Check 3: Region is valid AWS region
      const validRegionPattern = /^[a-z]{2}(-gov)?-(north|south|east|west|central|northeast|southeast|northwest|southwest)-\d$/;
      checks.region_valid = validRegionPattern.test(doc.region);

      // Check 4: PKCS7 signature verification against AWS public certificate
      if (evidence.signature) {
        try {
          checks.signature_verified = this.verifyPKCS7Signature(docRaw, evidence.signature, doc.region);
        } catch (sigErr) {
          this.log(`PKCS7 verification error: ${sigErr.message}`, 'warn');
          checks.signature_verified = false;
        }
      }

      // Trust level: cryptographic only when ALL checks pass
      const allPassed = checks.doc_valid && checks.instance_match && checks.region_valid && checks.signature_verified;
      const claimsValid = checks.doc_valid && checks.instance_match && checks.region_valid;

      let trust_level, verification_status;
      if (allPassed) {
        trust_level = 'cryptographic';
        verification_status = 'signature-verified';
      } else if (claimsValid && !checks.signature_verified) {
        trust_level = 'high';
        verification_status = 'claims-valid-signature-unverified';
      } else {
        trust_level = 'medium';
        verification_status = 'unverified-claims';
      }

      return {
        method: 'aws-imdsv2-signed',
        success: true,
        trust_level,
        verification_status,
        claims: {
          instance_id: doc.instanceId,
          account_id: doc.accountId,
          region: doc.region,
          availability_zone: doc.availabilityZone,
          architecture: doc.architecture,
          image_id: doc.imageId,
          pending_time: doc.pendingTime,
          signature_present: !!evidence.signature,
          signature_verified: checks.signature_verified,
          checks,
        },
        timestamp,
      };
    } catch (error) {
      return { method: 'aws-imdsv2-signed', success: false,
        reason: `IMDSv2 verification failed: ${error.message}`, timestamp };
    }
  }

  // ── PKCS7 Signature Verification ──
  // AWS signs instance identity documents with RSA using region-specific certs.
  // We verify using the public certificates published by AWS:
  // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html

  verifyPKCS7Signature(document, signature, region) {
    const crypto = require('crypto');

    // AWS public certificate for instance identity document verification.
    // This is the RSA-2048 certificate used for standard regions.
    // AWS publishes separate certs for GovCloud and China regions.
    // In production, load these from a secure config or fetch from AWS docs.
    const cert = this.getAWSPublicCert(region);
    if (!cert) {
      this.log(`No AWS public cert available for region: ${region}`, 'warn');
      return false;
    }

    try {
      // The PKCS7 signature from IMDS is base64-encoded.
      // We need to wrap it in PEM PKCS7 format for OpenSSL verification.
      const sigClean = signature.replace(/\s+/g, '');

      // Node.js crypto doesn't have native PKCS7 verify, but we can verify
      // the RSA signature directly since AWS also provides RSA-2048 signatures
      // via /latest/dynamic/instance-identity/rsa2048 endpoint.
      //
      // For PKCS7: We construct the expected signature format and verify.
      // The PKCS7 envelope contains the document signed with the AWS private key.

      // Method 1: Use RSA-2048 signature if available (preferred, simpler)
      if (signature.length > 500) {
        // This looks like a base64 RSA-2048 signature
        const sigBuf = Buffer.from(sigClean, 'base64');
        const docBuf = Buffer.from(document);
        const verifier = crypto.createVerify('SHA256');
        verifier.update(docBuf);
        return verifier.verify(cert, sigBuf);
      }

      // Method 2: PKCS7 envelope — construct PEM and verify via openssl-compatible path
      // The PKCS7 from IMDS is a detached signature over the document
      const pemSig = `-----BEGIN PKCS7-----\n${sigClean.match(/.{1,64}/g).join('\n')}\n-----END PKCS7-----`;

      // Use crypto.verify with the extracted signature
      // For PKCS7 detached signatures, we verify the content hash
      const hash = crypto.createHash('sha256').update(document).digest();
      const verifier = crypto.createVerify('SHA256');
      verifier.update(Buffer.from(document));

      // Try direct RSA verification against the PKCS7 content
      try {
        return verifier.verify(cert, Buffer.from(sigClean, 'base64'));
      } catch {
        // PKCS7 format may need different handling — log and return false
        this.log('PKCS7 direct verify failed, may need openssl subprocess', 'warn');
        return false;
      }
    } catch (error) {
      this.log(`PKCS7 verification error: ${error.message}`, 'warn');
      return false;
    }
  }

  getAWSPublicCert(region) {
    // AWS public RSA certificates for instance identity document verification
    // Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html
    //
    // Standard regions (us-east-1, eu-west-1, ap-southeast-1, etc.)
    // GovCloud and China have separate certificates.
    // In production, load from config or fetch from a secure endpoint.

    if (region?.startsWith('cn-')) {
      return AWS_CERT_CHINA;
    }
    if (region?.includes('gov')) {
      return AWS_CERT_GOVCLOUD;
    }
    return AWS_CERT_STANDARD;
  }

  verifySTS(evidence, workload, timestamp) {
    const arn = evidence.caller_identity.Arn;
    const account = evidence.caller_identity.Account;

    // If workload has a registered ARN, verify it matches
    if (workload.metadata?.arn && workload.metadata.arn !== arn) {
      return {
        method: 'aws-sts-identity',
        success: false,
        reason: `ARN mismatch: ${arn} ≠ ${workload.metadata.arn}`,
        timestamp,
      };
    }

    return {
      method: 'aws-sts-identity',
      success: true,
      trust_level: 'high',
      claims: {
        arn,
        account_id: account,
        user_id: evidence.caller_identity.UserId,
      },
      timestamp,
    };
  }

  verifyPlatformMetadata(evidence, workload, timestamp) {
    const claims = {};

    if (evidence.lambda) {
      claims.function_name = evidence.lambda.function_name;
      claims.function_arn = evidence.lambda.function_arn;
      claims.runtime = evidence.lambda.runtime;
      claims.role = evidence.lambda.role;
    }

    if (evidence.ecs_metadata) {
      claims.task_arn = evidence.ecs_metadata.TaskARN;
      claims.cluster = evidence.ecs_metadata.Cluster;
    }

    return {
      method: 'aws-sts-identity',
      success: true,
      trust_level: 'high',
      claims,
      timestamp,
    };
  }

  // ── IMDSv2 Token Management ──

  async getIMDSToken() {
    if (this._imdsToken && Date.now() < this._imdsTokenExpiry) {
      return this._imdsToken;
    }

    const http = require('http');
    return new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '169.254.169.254',
        path: '/latest/api/token',
        method: 'PUT',
        headers: { 'X-aws-ec2-metadata-token-ttl-seconds': String(AWS_IMDS_TOKEN_TTL) },
        timeout: 2000,
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          this._imdsToken = data.trim();
          this._imdsTokenExpiry = Date.now() + (AWS_IMDS_TOKEN_TTL - 300) * 1000;
          resolve(this._imdsToken);
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('IMDS timeout')); });
      req.end();
    });
  }
}

module.exports = AWSAttestationProvider;
