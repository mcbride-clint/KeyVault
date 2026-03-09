using Microsoft.EntityFrameworkCore;
using KeyVaultService.Data;
using KeyVaultService.Models;

namespace KeyVaultService.Services;

public interface ISecretsService
{
    Task<IEnumerable<Secret>> ListAsync(bool includeInactive = false);
    Task<Secret?> GetByIdAsync(long id);
    Task<Secret?> GetByNameAsync(string name);
    Task<string?> ReadValueAsync(long id, string principal, bool isAdmin);
    Task<Secret> CreateAsync(string name, string? description, SecretType type, string plainValue, string createdBy);
    Task UpdateValueAsync(long id, string plainValue, string updatedBy);
    Task DeactivateAsync(long id, string deletedBy);
    Task<bool> PrincipalHasReadAccessAsync(long secretId, string username, IEnumerable<string> groups, bool isApiKey = false);
}

public class SecretsService : ISecretsService
{
    private readonly KeyVaultDbContext _db;
    private readonly IEncryptionService _enc;
    private readonly IAuditService _audit;

    public SecretsService(KeyVaultDbContext db, IEncryptionService enc, IAuditService audit)
    {
        _db    = db;
        _enc   = enc;
        _audit = audit;
    }

    public Task<IEnumerable<Secret>> ListAsync(bool includeInactive = false)
    {
        var q = _db.Secrets.AsQueryable();
        if (!includeInactive) q = q.Where(s => s.IsActive);
        return Task.FromResult<IEnumerable<Secret>>(q.OrderBy(s => s.Name).AsEnumerable());
    }

    public Task<Secret?> GetByIdAsync(long id) =>
        _db.Secrets.Include(s => s.Grants).FirstOrDefaultAsync(s => s.Id == id);

    public Task<Secret?> GetByNameAsync(string name) =>
        _db.Secrets.Include(s => s.Grants).FirstOrDefaultAsync(s => s.Name == name && s.IsActive);

    public async Task<string?> ReadValueAsync(long id, string principal, bool isAdmin)
    {
        var secret = await _db.Secrets.FindAsync(id);
        if (secret == null || !secret.IsActive) return null;

        var value = _enc.Decrypt(secret.EncryptedValue, secret.ProtectedKey);
        await _audit.LogAsync(id, principal, "READ");
        return value;
    }

    public async Task<Secret> CreateAsync(string name, string? description, SecretType type, string plainValue, string createdBy)
    {
        var (encVal, protKey) = _enc.Encrypt(plainValue);
        var now = DateTime.UtcNow;

        var secret = new Secret
        {
            Name           = name,
            Description    = description,
            Type           = type,
            EncryptedValue = encVal,
            ProtectedKey   = protKey,
            CreatedBy      = createdBy,
            CreatedAt      = now,
            UpdatedAt      = now,
            IsActive       = true
        };

        _db.Secrets.Add(secret);
        await _db.SaveChangesAsync();
        await _audit.LogAsync(secret.Id, createdBy, "CREATE", $"Type={type}");
        return secret;
    }

    public async Task UpdateValueAsync(long id, string plainValue, string updatedBy)
    {
        var secret = await _db.Secrets.FindAsync(id)
                    ?? throw new KeyNotFoundException($"Secret {id} not found.");

        var (encVal, protKey) = _enc.Encrypt(plainValue);
        secret.EncryptedValue = encVal;
        secret.ProtectedKey   = protKey;
        secret.UpdatedAt      = DateTime.UtcNow;

        await _db.SaveChangesAsync();
        await _audit.LogAsync(id, updatedBy, "UPDATE");
    }

    public async Task DeactivateAsync(long id, string deletedBy)
    {
        var secret = await _db.Secrets.FindAsync(id)
                    ?? throw new KeyNotFoundException($"Secret {id} not found.");
        secret.IsActive  = false;
        secret.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        await _audit.LogAsync(id, deletedBy, "DELETE");
    }

    public async Task<bool> PrincipalHasReadAccessAsync(long secretId, string username, IEnumerable<string> groups, bool isApiKey = false)
    {
        var grants = await _db.Grants
            .Where(g => g.SecretId == secretId && g.CanRead)
            .ToListAsync();

        return grants.Any(g =>
            (g.PrincipalType == PrincipalType.WindowsUser  && g.PrincipalValue.Equals(username, StringComparison.OrdinalIgnoreCase)) ||
            (g.PrincipalType == PrincipalType.WindowsGroup && groups.Any(grp => grp.Equals(g.PrincipalValue, StringComparison.OrdinalIgnoreCase))) ||
            (g.PrincipalType == PrincipalType.ApiKey       && isApiKey && g.PrincipalValue == username)
        );
    }
}
