// =============================================================================
// Attestation Helpers - Platform attestation utilities
// =============================================================================
// STATUS: Verification functions are NOT YET IMPLEMENTED.
// Each function throws a clear error so callers know not to rely on them.
// Implementation TODO is tracked per-function below.
// =============================================================================

/**
 * Verify AWS IMDSv2 instance identity document signature.
 * TODO: Verify PKCS7 signature using AWS regional certificate bundle from:
 *   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-pkcs7.html
 *
 * @param {string} document - Instance identity document (JSON string)
 * @param {string} signature - PKCS7 signature (base64)
 * @param {string} region - AWS region (used to fetch correct cert)
 * @returns {Promise<boolean>}
 */
async function verifyAWSSignature(document, signature, region) {
  throw new Error(
    'verifyAWSSignature not implemented. ' +
    'TODO: Verify PKCS7 using AWS regional certificate bundle. ' +
    'See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-pkcs7.html'
  );
}

/**
 * Verify GCP instance identity JWT token.
 * TODO: Verify JWT signature using Google OAuth2 public keys from:
 *   https://www.googleapis.com/oauth2/v1/certs
 *
 * @param {string} token - JWT token from GCP metadata service
 * @returns {Promise<Object>} Decoded and verified token payload
 */
async function verifyGCPToken(token) {
  throw new Error(
    'verifyGCPToken not implemented. ' +
    'TODO: Verify JWT using Google OAuth2 certs at https://www.googleapis.com/oauth2/v1/certs. ' +
    'Use jsonwebtoken or google-auth-library.'
  );
}

/**
 * Verify Azure Managed Identity token.
 * TODO: Verify using Azure AD JWKS endpoint:
 *   https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
 *
 * @param {string} token - Azure MSI access token
 * @returns {Promise<Object>} Decoded and verified token payload
 */
async function verifyAzureToken(token) {
  throw new Error(
    'verifyAzureToken not implemented. ' +
    'TODO: Verify JWT using Azure AD JWKS. Use @azure/identity or jsonwebtoken.'
  );
}

/**
 * Verify SPIFFE X.509 SVID certificate chain.
 * TODO: Verify certificate chain against SPIRE trust bundle using node:crypto or node-forge.
 *
 * @param {Object} certificate - X.509 certificate (PEM or DER)
 * @param {Object} trustBundle - SPIRE trust bundle (JWKs or PEM certificates)
 * @returns {Promise<boolean>}
 */
async function verifySPIFFESVID(certificate, trustBundle) {
  throw new Error(
    'verifySPIFFESVID not implemented. ' +
    'TODO: Verify X.509 chain against trust bundle using node:crypto. ' +
    'See SPIFFE spec: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md'
  );
}

module.exports = {
  verifyAWSSignature,
  verifyGCPToken,
  verifyAzureToken,
  verifySPIFFESVID,
};
