namespace KeyVaultService.Models;

public enum SecretType { Password, ConnectionString, ApiKey, Certificate, Custom }
public enum PrincipalType { WindowsUser, WindowsGroup, ApiKey }

public class Secret
{
    public long Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public SecretType Type { get; set; }
    public string EncryptedValue { get; set; } = string.Empty;
    public string ProtectedKey { get; set; } = string.Empty;   // DPAPI-protected AES key (Base64)
    public string CreatedBy { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsActive { get; set; } = true;

    public ICollection<Grant> Grants { get; set; } = new List<Grant>();
    public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
}

public class Grant
{
    public long Id { get; set; }
    public long SecretId { get; set; }
    public PrincipalType PrincipalType { get; set; }
    public string PrincipalValue { get; set; } = string.Empty;  // username, group name, or ApiKey.Id
    public bool CanRead { get; set; } = true;
    public bool CanAdmin { get; set; } = false;
    public string GrantedBy { get; set; } = string.Empty;
    public DateTime GrantedAt { get; set; }

    public Secret Secret { get; set; } = null!;
}

public class ApiKeyRecord
{
    public long Id { get; set; }
    public string Label { get; set; } = string.Empty;
    public string KeyHash { get; set; } = string.Empty;         // SHA-256 hash of the raw key
    public string CreatedBy { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? LastUsed { get; set; }
    public bool IsActive { get; set; } = true;
}

public class AuditLog
{
    public long Id { get; set; }
    public long? SecretId { get; set; }
    public string Principal { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;          // READ, CREATE, UPDATE, DELETE, GRANT, REVOKE
    public string? Detail { get; set; }
    public string? IpAddress { get; set; }
    public DateTime Timestamp { get; set; }

    public Secret? Secret { get; set; }
}
