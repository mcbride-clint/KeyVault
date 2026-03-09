using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.EntityFrameworkCore;
using Serilog;
using KeyVaultService.Data;
using KeyVaultService.Middleware;
using KeyVaultService.Services;

// ─── Serilog bootstrap ───────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(new ConfigurationBuilder()
        .AddJsonFile("appsettings.json").Build())
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseSerilog((ctx, cfg) => cfg.ReadFrom.Configuration(ctx.Configuration));

    // ── Database ─────────────────────────────────────────────────────────────
    builder.Services.AddDbContext<KeyVaultDbContext>(opts =>
        opts.UseOracle(builder.Configuration.GetConnectionString("Oracle")));

    // ── Authentication ────────────────────────────────────────────────────────
    builder.Services.AddAuthentication(options =>
    {
        // Default to Windows (Negotiate); API key handler is additive
        options.DefaultAuthenticateScheme = NegotiateDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme    = NegotiateDefaults.AuthenticationScheme;
    })
    .AddNegotiate()                            // Windows / Kerberos / NTLM
    .AddScheme<ApiKeyAuthOptions, ApiKeyAuthHandler>(
        ApiKeyAuthDefaults.SchemeName, _ => { });

    // ── Authorization ─────────────────────────────────────────────────────────
    builder.Services.AddAuthorization(opts =>
    {
        // Admins = members of the AD group named in config
        var adminGroup = builder.Configuration["Authorization:AdminGroup"] ?? "KeyVaultAdmins";
        opts.AddPolicy("AdminOnly", p => p.RequireRole(adminGroup));
    });

    // ── Application services ──────────────────────────────────────────────────
    builder.Services.AddScoped<IEncryptionService, DpapiAesEncryptionService>();
    builder.Services.AddScoped<IAuditService,      AuditService>();
    builder.Services.AddScoped<ISecretsService,    SecretsService>();
    builder.Services.AddScoped<IGrantsService,     GrantsService>();
    builder.Services.AddScoped<IApiKeyService,     ApiKeyService>();

    // ── Razor Pages + Controllers ─────────────────────────────────────────────
    builder.Services.AddRazorPages(opts =>
    {
        opts.Conventions.AuthorizeFolder("/", "AdminOnly");
    });
    builder.Services.AddControllers();

    // ─────────────────────────────────────────────────────────────────────────
    var app = builder.Build();

    if (!app.Environment.IsDevelopment())
        app.UseExceptionHandler("/Error");

    app.UseStaticFiles();
    app.UseSerilogRequestLogging();
    app.UseRouting();

    // Multi-scheme auth: try Windows first; if the X-Api-Key header is present the
    // ApiKeyAuthHandler will kick in and authenticate via that scheme instead.
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseMiddleware<PrincipalResolutionMiddleware>();

    app.MapRazorPages();
    app.MapControllers();

    // ── EF Core – ensure DB objects exist on startup (dev convenience) ────────
    if (app.Environment.IsDevelopment())
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeyVaultDbContext>();
        db.Database.EnsureCreated();   // For prod: run 001_CreateTables.sql manually
    }

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application start-up failed");
}
finally
{
    Log.CloseAndFlush();
}
