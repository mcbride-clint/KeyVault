using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using KeyVaultService.Services;

namespace KeyVaultService.Middleware;

public static class ApiKeyAuthDefaults
{
    public const string SchemeName = "ApiKey";
    public const string HeaderName = "X-Api-Key";
}

public class ApiKeyAuthOptions : AuthenticationSchemeOptions { }

public class ApiKeyAuthHandler : AuthenticationHandler<ApiKeyAuthOptions>
{
    private readonly IApiKeyService _apiKeyService;

    public ApiKeyAuthHandler(
        IOptionsMonitor<ApiKeyAuthOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IApiKeyService apiKeyService)
        : base(options, logger, encoder)
    {
        _apiKeyService = apiKeyService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ApiKeyAuthDefaults.HeaderName, out var rawKey))
            return AuthenticateResult.NoResult();

        var principalId = await _apiKeyService.ValidateAsync(rawKey.ToString());
        if (principalId == null)
            return AuthenticateResult.Fail("Invalid or inactive API key.");

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, principalId),
            new Claim(ClaimTypes.Name, $"apikey:{principalId}"),
            new Claim("ApiKeyId", principalId)
        };

        var identity  = new ClaimsIdentity(claims, ApiKeyAuthDefaults.SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket    = new AuthenticationTicket(principal, ApiKeyAuthDefaults.SchemeName);

        return AuthenticateResult.Success(ticket);
    }
}

/// <summary>
/// Middleware that resolves the current principal name for audit / access-check purposes,
/// normalising both Windows (DOMAIN\user) and API key principals.
/// </summary>
public class PrincipalResolutionMiddleware
{
    private readonly RequestDelegate _next;
    public PrincipalResolutionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        // Resolved principal is stored in HttpContext.Items for downstream use
        var user = ctx.User;

        string principal;
        if (user.Identity?.AuthenticationType == ApiKeyAuthDefaults.SchemeName)
            principal = user.FindFirstValue("ApiKeyId") ?? "unknown-apikey";
        else
            principal = user.Identity?.Name ?? "anonymous";

        ctx.Items["Principal"] = principal;
        ctx.Items["IsApiKey"]  = user.Identity?.AuthenticationType == ApiKeyAuthDefaults.SchemeName;

        await _next(ctx);
    }
}

public static class PrincipalExtensions
{
    public static string GetPrincipal(this HttpContext ctx) =>
        ctx.Items["Principal"] as string ?? "anonymous";

    public static bool IsApiKeyAuth(this HttpContext ctx) =>
        ctx.Items["IsApiKey"] is true;
}
