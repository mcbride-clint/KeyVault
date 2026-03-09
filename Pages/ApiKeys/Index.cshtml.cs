using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using KeyVaultService.Middleware;
using KeyVaultService.Models;
using KeyVaultService.Services;

namespace KeyVaultService.Pages.ApiKeys;

[Authorize(Roles = "KeyVaultAdmins")]
public class IndexModel : PageModel
{
    private readonly IApiKeyService _apiKeys;

    public IEnumerable<ApiKeyRecord> ApiKeys { get; set; } = [];
    public string? NewKeyValue { get; set; }

    public IndexModel(IApiKeyService apiKeys) => _apiKeys = apiKeys;

    public async Task OnGetAsync()
    {
        ApiKeys     = await _apiKeys.ListAsync();
        NewKeyValue = TempData["NewKeyValue"] as string;
    }

    public async Task<IActionResult> OnPostCreateAsync(string label)
    {
        try
        {
            var (_, rawKey) = await _apiKeys.CreateAsync(label, HttpContext.GetPrincipal());
            TempData["NewKeyValue"] = rawKey;
            TempData["Success"]     = $"API key '{label}' created.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRevokeAsync(long id)
    {
        try
        {
            await _apiKeys.DeactivateAsync(id, HttpContext.GetPrincipal());
            TempData["Success"] = "API key revoked.";
        }
        catch (Exception ex)
        {
            TempData["Error"] = ex.Message;
        }
        return RedirectToPage();
    }
}
