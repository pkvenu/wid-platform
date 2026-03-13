# DEV-ONLY KEYS

These keys are for **local development only**. They are committed to the repository
intentionally so that `docker compose up` works without manual key generation.

**NEVER use these keys in production.**

For production, set one of:
- `JWT_PRIVATE_KEY` env var (base64-encoded PEM)
- `JWT_PRIVATE_KEY_FILE` env var (path to PEM file mounted as a secret)

Generate production keys:
```bash
node services/token-service/scripts/generate-keys.js /path/to/prod/keys
```
