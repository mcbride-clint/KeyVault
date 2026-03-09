using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using KeyVaultService.Data;
using KeyVaultService.Models;
using KeyVaultService.Services;

namespace KeyVaultService.Pages;

[Authorize(Roles = "KeyVaultAdmins")]
public class IndexModel : PageModel
{
    private readonly KeyVaultDbContext _db;
    private readonly IAuditService _audit;

    public int SecretCount     { get; set; }
    public int GrantCount      { get; set; }
    public int ApiKeyCount     { get; set; }
    public int RecentAuditCount{ get; set; }
    public IEnumerable<AuditLog> RecentLogs { get; set; } = [];

    public IndexModel(KeyVaultDbContext db, IAuditService audit)
    {
        _db    = db;
        _audit = audit;
    }

    public async Task OnGetAsync()
    {
        SecretCount      = await _db.Secrets.CountAsync(s => s.IsActive);
        GrantCount       = await _db.Grants.CountAsync();
        ApiKeyCount      = await _db.ApiKeys.CountAsync(k => k.IsActive);
        RecentAuditCount = await _db.AuditLogs.CountAsync(a => a.Timestamp >= DateTime.UtcNow.AddHours(-24));
        RecentLogs       = await _audit.GetRecentAsync(20);
    }
}
