using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using KeyVaultService.Models;
using KeyVaultService.Services;

namespace KeyVaultService.Pages;

[Authorize(Roles = "KeyVaultAdmins")]
public class AuditModel : PageModel
{
    private readonly IAuditService _audit;
    public IEnumerable<AuditLog> Logs { get; set; } = [];

    public AuditModel(IAuditService audit) => _audit = audit;

    public async Task OnGetAsync() => Logs = await _audit.GetRecentAsync(200);
}
