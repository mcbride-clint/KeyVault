using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using KeyVaultService.Data;
using KeyVaultService.Middleware;
using KeyVaultService.Models;
using KeyVaultService.Services;

namespace KeyVaultService.Pages.Secrets;

[Authorize(Policy = "AdminOnly")]
public class IndexModel : PageModel
{
    private readonly ISecretsService _secrets;
    private readonly KeyVaultDbContext _db;

    public IEnumerable<Secret> Secrets { get; set; } = [];

    public IndexModel(ISecretsService secrets, KeyVaultDbContext db)
    {
        _secrets = secrets;
        _db      = db;
    }

    public async Task OnGetAsync()
    {
        Secrets = await _db.Secrets
                           .Include(s => s.Grants)
                           .Where(s => s.IsActive)
                           .OrderBy(s => s.Name)
                           .ToListAsync();
    }

    public async Task<IActionResult> OnPostCreateAsync(string name, SecretType type, string? description, string value)
    {
        try
        {
            await _secrets.CreateAsync(name, description, type, value, HttpContext.GetPrincipal());
            TempData["Success"] = $"Secret '{name}' created.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostUpdateValueAsync(long id, string value)
    {
        try
        {
            await _secrets.UpdateValueAsync(id, value, HttpContext.GetPrincipal());
            TempData["Success"] = "Secret value updated.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeleteAsync(long id)
    {
        try
        {
            await _secrets.DeactivateAsync(id, HttpContext.GetPrincipal());
            TempData["Success"] = "Secret deactivated.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage();
    }
}
