using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using KeyVaultService.Middleware;
using KeyVaultService.Models;
using KeyVaultService.Services;

namespace KeyVaultService.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecretsController : ControllerBase
{
    private readonly ISecretsService _secrets;
    private readonly IGrantsService  _grants;
    private readonly IAuditService   _audit;

    public SecretsController(ISecretsService secrets, IGrantsService grants, IAuditService audit)
    {
        _secrets = secrets;
        _grants  = grants;
        _audit   = audit;
    }

    // GET /api/secrets/{name}  — retrieve the decrypted value
    [HttpGet("{name}")]
    public async Task<IActionResult> GetSecret(string name)
    {
        var secret = await _secrets.GetByNameAsync(name);
        if (secret == null) return NotFound();

        var principal  = HttpContext.GetPrincipal();
        var isApiKey   = HttpContext.IsApiKeyAuth();
        var groups     = User.Claims
                             .Where(c => c.Type == System.Security.Claims.ClaimTypes.GroupSid ||
                                         c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid")
                             .Select(c => c.Value)
                             .ToList();

        // Admins bypass grant check
        bool isAdmin = User.IsInRole("KeyVaultAdmins");
        if (!isAdmin)
        {
            var hasAccess = await _secrets.PrincipalHasReadAccessAsync(secret.Id, principal, groups, isApiKey);
            if (!hasAccess) return Forbid();
        }

        var value = await _secrets.ReadValueAsync(secret.Id, principal, isAdmin);
        return Ok(new { secret.Name, secret.Type, Value = value });
    }

    // GET /api/secrets — list metadata (no values)
    [HttpGet]
    [Authorize(Roles = "KeyVaultAdmins")]
    public async Task<IActionResult> List()
    {
        var all = await _secrets.ListAsync();
        return Ok(all.Select(s => new { s.Id, s.Name, s.Type, s.Description, s.CreatedBy, s.CreatedAt, s.UpdatedAt }));
    }
}
