using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using KeyVaultService.Data;
using KeyVaultService.Middleware;
using KeyVaultService.Models;
using KeyVaultService.Services;

namespace KeyVaultService.Pages.Grants;

[Authorize(Policy = "AdminOnly")]
public class IndexModel : PageModel
{
    private readonly IGrantsService _grants;
    private readonly KeyVaultDbContext _db;

    public Secret? SelectedSecret { get; set; }
    public IEnumerable<Grant> Grants { get; set; } = [];
    public IEnumerable<Secret> AllSecrets { get; set; } = [];

    public IndexModel(IGrantsService grants, KeyVaultDbContext db)
    {
        _grants = grants;
        _db     = db;
    }

    public async Task OnGetAsync(long? secretId)
    {
        if (secretId.HasValue)
        {
            SelectedSecret = await _db.Secrets.FindAsync(secretId.Value);
            if (SelectedSecret != null)
                Grants = await _grants.GetForSecretAsync(secretId.Value);
        }
        else
        {
            AllSecrets = await _db.Secrets
                                  .Include(s => s.Grants)
                                  .Where(s => s.IsActive)
                                  .OrderBy(s => s.Name)
                                  .ToListAsync();
        }
    }

    public async Task<IActionResult> OnPostAddAsync(long secretId, PrincipalType principalType, string principalValue, bool canRead, bool canAdmin)
    {
        try
        {
            await _grants.AddGrantAsync(secretId, principalType, principalValue, canRead, canAdmin, HttpContext.GetPrincipal());
            TempData["Success"] = "Grant added.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage(new { secretId });
    }

    public async Task<IActionResult> OnPostRevokeAsync(long grantId, long secretId)
    {
        try
        {
            await _grants.RevokeAsync(grantId, HttpContext.GetPrincipal());
            TempData["Success"] = "Grant revoked.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage(new { secretId });
    }
}
