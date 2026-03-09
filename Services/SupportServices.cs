using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using KeyVaultService.Data;
using KeyVaultService.Models;

namespace KeyVaultService.Services;

// ─────────────────────────────────────────────────────────────────────────────
//  Grants
// ─────────────────────────────────────────────────────────────────────────────
public interface IGrantsService
{
    Task<IEnumerable<Grant>> GetForSecretAsync(long secretId);
    Task<Grant> AddGrantAsync(long secretId, PrincipalType type, string value, bool canRead, bool canAdmin, string grantedBy);
    Task RevokeAsync(long grantId, string revokedBy);
}

public class GrantsService : IGrantsService
{
    private readonly KeyVaultDbContext _db;
    private readonly IAuditService _audit;

    public GrantsService(KeyVaultDbContext db, IAuditService audit)
    {
        _db    = db;
        _audit = audit;
    }

    public async Task<IEnumerable<Grant>> GetForSecretAsync(long secretId) =>
        await _db.Grants.Where(g => g.SecretId == secretId).ToListAsync();

    public async Task<Grant> AddGrantAsync(long secretId, PrincipalType type, string value, bool canRead, bool canAdmin, string grantedBy)
    {
        var grant = new Grant
        {
            SecretId       = secretId,
            PrincipalType  = type,
            PrincipalValue = value,
            CanRead        = canRead,
            CanAdmin       = canAdmin,
            GrantedBy      = grantedBy,
            GrantedAt      = DateTime.UtcNow
        };
        _db.Grants.Add(grant);
        await _db.SaveChangesAsync();
        await _audit.LogAsync(secretId, grantedBy, "GRANT", $"{type}:{value}");
        return grant;
    }

    public async Task RevokeAsync(long grantId, string revokedBy)
    {
        var grant = await _db.Grants.FindAsync(grantId)
                   ?? throw new KeyNotFoundException($"Grant {grantId} not found.");
        _db.Grants.Remove(grant);
        await _db.SaveChangesAsync();
        await _audit.LogAsync(grant.SecretId, revokedBy, "REVOKE", $"{grant.PrincipalType}:{grant.PrincipalValue}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  API Keys
// ─────────────────────────────────────────────────────────────────────────────
public interface IApiKeyService
{
    Task<IEnumerable<ApiKeyRecord>> ListAsync();
    Task<(ApiKeyRecord record, string rawKey)> CreateAsync(string label, string createdBy);
    Task DeactivateAsync(long id, string deactivatedBy);

    /// <summary>Validates a raw key; returns the ApiKeyRecord.Id as string principal on success.</summary>
    Task<string?> ValidateAsync(string rawKey);
}

public class ApiKeyService : IApiKeyService
{
    private readonly KeyVaultDbContext _db;
    private readonly IAuditService _audit;

    public ApiKeyService(KeyVaultDbContext db, IAuditService audit)
    {
        _db    = db;
        _audit = audit;
    }

    public async Task<IEnumerable<ApiKeyRecord>> ListAsync() =>
        await _db.ApiKeys.OrderByDescending(k => k.CreatedAt).ToListAsync();

    public async Task<(ApiKeyRecord record, string rawKey)> CreateAsync(string label, string createdBy)
    {
        // Raw key = "kvs_" + 40 random URL-safe chars
        var raw  = "kvs_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(30))
                                    .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var hash = HashKey(raw);

        var record = new ApiKeyRecord
        {
            Label     = label,
            KeyHash   = hash,
            CreatedBy = createdBy,
            CreatedAt = DateTime.UtcNow,
            IsActive  = true
        };
        _db.ApiKeys.Add(record);
        await _db.SaveChangesAsync();
        await _audit.LogAsync(null, createdBy, "APIKEY_CREATE", label);
        return (record, raw);
    }

    public async Task DeactivateAsync(long id, string deactivatedBy)
    {
        var key = await _db.ApiKeys.FindAsync(id)
                 ?? throw new KeyNotFoundException($"ApiKey {id} not found.");
        key.IsActive = false;
        await _db.SaveChangesAsync();
        await _audit.LogAsync(null, deactivatedBy, "APIKEY_REVOKE", key.Label);
    }

    public async Task<string?> ValidateAsync(string rawKey)
    {
        var hash   = HashKey(rawKey);
        var record = await _db.ApiKeys.FirstOrDefaultAsync(k => k.KeyHash == hash && k.IsActive);
        if (record == null) return null;
        record.LastUsed = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return record.Id.ToString();    // returned as the "principal" string
    }

    private static string HashKey(string raw)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Audit
// ─────────────────────────────────────────────────────────────────────────────
public interface IAuditService
{
    Task LogAsync(long? secretId, string principal, string action, string? detail = null, string? ip = null);
    Task<IEnumerable<AuditLog>> GetRecentAsync(int count = 100);
    Task<IEnumerable<AuditLog>> GetForSecretAsync(long secretId);
}

public class AuditService : IAuditService
{
    private readonly KeyVaultDbContext _db;

    public AuditService(KeyVaultDbContext db) => _db = db;

    public async Task LogAsync(long? secretId, string principal, string action, string? detail = null, string? ip = null)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            SecretId  = secretId,
            Principal = principal,
            Action    = action,
            Detail    = detail,
            IpAddress = ip,
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }

    public async Task<IEnumerable<AuditLog>> GetRecentAsync(int count = 100) =>
        await _db.AuditLogs
                 .Include(a => a.Secret)
                 .OrderByDescending(a => a.Timestamp)
                 .Take(count)
                 .ToListAsync();

    public async Task<IEnumerable<AuditLog>> GetForSecretAsync(long secretId) =>
        await _db.AuditLogs
                 .Where(a => a.SecretId == secretId)
                 .OrderByDescending(a => a.Timestamp)
                 .ToListAsync();
}
