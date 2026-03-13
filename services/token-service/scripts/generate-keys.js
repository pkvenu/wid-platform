#!/usr/bin/env node
// =============================================================================
// ES256 Key Pair Generator for WID Token Service
// Generates ECDSA P-256 key pair + JWKS JSON with RFC 7638 thumbprint as kid
// =============================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

function computeJWKThumbprint(jwk) {
  // RFC 7638: for EC keys, use {"crv","kty","x","y"} in lexicographic order
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  const hash = crypto.createHash('sha256').update(canonical).digest();
  return hash.toString('base64url');
}

function pemToJWK(publicKeyPem) {
  const keyObject = crypto.createPublicKey(publicKeyPem);
  const jwk = keyObject.export({ format: 'jwk' });
  return jwk;
}

function main() {
  const outputDir = process.argv[2] || path.join(__dirname, '..', 'keys', 'dev');

  console.log(`Generating ES256 key pair in: ${outputDir}`);

  // Generate key pair
  const { privateKey, publicKey } = generateKeyPair();

  // Convert to JWK and compute kid
  const jwk = pemToJWK(publicKey);
  const kid = computeJWKThumbprint(jwk);

  // Build JWKS document
  const jwks = {
    keys: [
      {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        kid,
        use: 'sig',
        alg: 'ES256',
      },
    ],
  };

  // Ensure output directory exists
  fs.mkdirSync(outputDir, { recursive: true });

  // Write files
  fs.writeFileSync(path.join(outputDir, 'ec-private.pem'), privateKey, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'ec-public.pem'), publicKey, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'jwks.json'), JSON.stringify(jwks, null, 2), 'utf8');

  console.log(`  ec-private.pem  (ECDSA P-256 private key)`);
  console.log(`  ec-public.pem   (ECDSA P-256 public key)`);
  console.log(`  jwks.json       (JWKS with kid=${kid})`);
  console.log('Done.');
}

main();
