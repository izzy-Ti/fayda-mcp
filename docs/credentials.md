# Credential Ownership & Cryptography

The `fayda-mcp` library adheres to a zero-secret design:
- **No hardcoded credentials**: The library contains zero client IDs, secret keys, or test credentials.
- **Host ownership**: The integrating host application owns and manages its Relying Party registration with National ID / Fayda (eSignet).
- **Private key isolation**: Private keys never leave the host environment and are never transmitted over the Model Context Protocol.

---

## 1. Authentication Method: `private_key_jwt`

Fayda eSignet uses RFC 7523 `private_key_jwt` authentication at the token endpoint instead of shared client secrets.

To authenticate:
1. The host signs an assertion JWT using its private RSA key (`RS256`).
2. Fayda verifies the signature using the host's public JWKS registered during Relying Party onboarding.
3. No shared secret is ever transmitted over the wire.

---

## 2. Generating Your Keypair

Generate a standard 2048-bit or 4096-bit RSA keypair:

```bash
# Generate private key
openssl genrsa -out fayda_private_key.pem 2048

# Extract public key to register with Fayda
openssl rsa -in fayda_private_key.pem -pubout -out fayda_public_key.pem
```

Alternatively, you can export a JSON Web Key (JWK) containing the `kty: "RSA"`, `kid`, `n`, and `e` fields for registration in the Fayda Developer Portal.

---

## 3. Configuring the Private Key

### Option A: Local File Path
Provide the path to your PEM or JWK private key file via configuration:

```python
from fayda_mcp import FaydaConfig

config = FaydaConfig(
    client_id="my_registered_client_id",
    redirect_uri="https://app.example/callback",
    signing_key_path="/run/secrets/fayda_private_key.pem",
    ...,
)
```

### Option B: Cloud Secret Managers (`KeyProvider` Interface)
In production, avoid storing private keys on disk. Implement the `KeyProvider` protocol to resolve keys from AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault:

```python
from fayda_mcp.secrets.protocols import KeyProvider

class VaultKeyProvider(KeyProvider):
    async def get_private_key(self) -> str:
        # Fetch private key PEM from HashiCorp Vault or AWS Secrets Manager
        return await vault_client.read_secret("fayda/private_key")

service = FaydaVerificationService(
    config=config,
    sessions=sessions,
    results=results,
    key_provider=VaultKeyProvider(),
)
```
