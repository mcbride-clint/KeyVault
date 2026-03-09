# KeyVaultService

A self-hosted secrets management service for air-gapped internal networks.
Built with ASP.NET Core 8, Oracle (ODP.NET), Razor Pages admin UI, and dual authentication (Windows Auth + API Keys).

---

## Architecture Overview

```
Browser / Windows Client          Non-Windows Client / Pipeline
         │  (Negotiate / Kerberos)          │  (X-Api-Key header)
         └─────────────┬────────────────────┘
                       ▼
             ASP.NET Core on IIS
             ┌──────────────────────┐
             │  Auth: Windows +     │
             │        API Key       │
             │  Admin: Razor Pages  │
             │  API:  /api/secrets  │
             └──────────┬───────────┘
                        │
             ┌──────────▼───────────┐
             │   SecretsService     │
             │   GrantsService      │
             │   ApiKeyService      │
             │   AuditService       │
             └──────────┬───────────┘
                        │
             ┌──────────▼───────────┐
             │  Oracle DB           │
             │  KV_SECRETS          │
             │  KV_GRANTS           │
             │  KV_API_KEYS         │
             │  KV_AUDIT_LOG        │
             └──────────────────────┘
```

---

## Setup

### 1. Database
Run `Data/001_CreateTables.sql` against your Oracle schema once.

### 2. Connection String
Edit `appsettings.json`:
```json
"ConnectionStrings": {
  "Oracle": "User Id=kvs_owner;Password=SECRET;Data Source=your-oracle:1521/ORCL"
}
```

### 3. Admin Group
By default, users in the AD group **KeyVaultAdmins** get full admin access.
Change this in `appsettings.json`:
```json
"Authorization": {
  "AdminGroup": "YourDomainGroup"
}
```

### 4. IIS Deployment
```
dotnet publish -c Release -o C:\inetpub\keyvault
```
- Create an IIS site pointing to that folder
- **Application Pool**: No Managed Code, identity = a domain service account
- **Authentication**: Windows Auth ON, Anonymous Auth OFF (matches web.config)
- Ensure the service account has DPAPI LocalMachine key access (default for domain accounts)

---

## Authentication

### Windows / AD
Any browser or .NET `HttpClient` using Windows credentials is automatically authenticated via Kerberos/NTLM.

### API Keys
Send the header on every request:
```
X-Api-Key: kvs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```
Generate keys from the **API Keys** admin page. Keys are hashed (SHA-256) at rest — the raw value is shown only once.

---

## REST API

### Retrieve a secret value
```http
GET /api/secrets/{name}
Authorization: Negotiate ...   OR   X-Api-Key: kvs_...

200 OK
{
  "name": "prod-db-password",
  "type": "Password",
  "value": "supersecret"
}
```

### List secrets (admins only)
```http
GET /api/secrets
```

---

## Encryption Design

Each secret is encrypted with a **unique AES-256-GCM key**.
That key is protected at rest with **Windows DPAPI (LocalMachine scope)**, tying it to the host machine's TPM/key store.

```
Secret value  ──AES-256-GCM──►  EncryptedValue  (stored in DB)
AES key       ──DPAPI.Protect──► ProtectedKey    (stored in DB)
```

Even a full DB dump is useless without access to the host machine's DPAPI keys.

---

## Admin UI Pages

| Page | Path |
|------|------|
| Dashboard | `/` |
| Secrets | `/Secrets` |
| Access Grants | `/Grants` |
| API Keys | `/ApiKeys` |
| Audit Log | `/Audit` |

---

## Security Notes

- Admin UI is restricted to `KeyVaultAdmins` AD group
- All reads, writes, grants, and revocations are written to `KV_AUDIT_LOG`
- API key raw values are never stored — only their SHA-256 hash
- Rotate secrets regularly; the **Update Value** button re-encrypts with a new AES key
- Run under a dedicated low-privilege domain service account
- Consider TLS termination at the IIS binding or a reverse proxy
