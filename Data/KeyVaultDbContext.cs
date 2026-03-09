using Microsoft.EntityFrameworkCore;
using KeyVaultService.Models;

namespace KeyVaultService.Data;

public class KeyVaultDbContext : DbContext
{
    public KeyVaultDbContext(DbContextOptions<KeyVaultDbContext> options) : base(options) { }

    public DbSet<Secret> Secrets => Set<Secret>();
    public DbSet<Grant> Grants => Set<Grant>();
    public DbSet<ApiKeyRecord> ApiKeys => Set<ApiKeyRecord>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // ── Secrets ──────────────────────────────────────────────────────────
        modelBuilder.Entity<Secret>(e =>
        {
            e.ToTable("KV_SECRETS");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasColumnName("ID").UseIdentityColumn();
            e.Property(x => x.Name).HasColumnName("NAME").HasMaxLength(200).IsRequired();
            e.Property(x => x.Description).HasColumnName("DESCRIPTION").HasMaxLength(1000);
            e.Property(x => x.Type).HasColumnName("TYPE").HasConversion<string>().HasMaxLength(30);
            e.Property(x => x.EncryptedValue).HasColumnName("ENCRYPTED_VALUE").HasColumnType("CLOB").IsRequired();
            e.Property(x => x.ProtectedKey).HasColumnName("PROTECTED_KEY").HasColumnType("CLOB").IsRequired();
            e.Property(x => x.CreatedBy).HasColumnName("CREATED_BY").HasMaxLength(200).IsRequired();
            e.Property(x => x.CreatedAt).HasColumnName("CREATED_AT").IsRequired();
            e.Property(x => x.UpdatedAt).HasColumnName("UPDATED_AT").IsRequired();
            e.Property(x => x.IsActive).HasColumnName("IS_ACTIVE").HasConversion<int>();
            e.HasIndex(x => x.Name).IsUnique().HasDatabaseName("UQ_KV_SECRETS_NAME");
        });

        // ── Grants ───────────────────────────────────────────────────────────
        modelBuilder.Entity<Grant>(e =>
        {
            e.ToTable("KV_GRANTS");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasColumnName("ID").UseIdentityColumn();
            e.Property(x => x.SecretId).HasColumnName("SECRET_ID").IsRequired();
            e.Property(x => x.PrincipalType).HasColumnName("PRINCIPAL_TYPE").HasConversion<string>().HasMaxLength(30);
            e.Property(x => x.PrincipalValue).HasColumnName("PRINCIPAL_VALUE").HasMaxLength(300).IsRequired();
            e.Property(x => x.CanRead).HasColumnName("CAN_READ").HasConversion<int>();
            e.Property(x => x.CanAdmin).HasColumnName("CAN_ADMIN").HasConversion<int>();
            e.Property(x => x.GrantedBy).HasColumnName("GRANTED_BY").HasMaxLength(200).IsRequired();
            e.Property(x => x.GrantedAt).HasColumnName("GRANTED_AT").IsRequired();
            e.HasOne(x => x.Secret).WithMany(s => s.Grants).HasForeignKey(x => x.SecretId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.SecretId, x.PrincipalType, x.PrincipalValue }).IsUnique().HasDatabaseName("UQ_KV_GRANTS");
        });

        // ── ApiKeys ───────────────────────────────────────────────────────────
        modelBuilder.Entity<ApiKeyRecord>(e =>
        {
            e.ToTable("KV_API_KEYS");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasColumnName("ID").UseIdentityColumn();
            e.Property(x => x.Label).HasColumnName("LABEL").HasMaxLength(200).IsRequired();
            e.Property(x => x.KeyHash).HasColumnName("KEY_HASH").HasMaxLength(100).IsRequired();
            e.Property(x => x.CreatedBy).HasColumnName("CREATED_BY").HasMaxLength(200).IsRequired();
            e.Property(x => x.CreatedAt).HasColumnName("CREATED_AT").IsRequired();
            e.Property(x => x.LastUsed).HasColumnName("LAST_USED");
            e.Property(x => x.IsActive).HasColumnName("IS_ACTIVE").HasConversion<int>();
            e.HasIndex(x => x.KeyHash).IsUnique().HasDatabaseName("UQ_KV_API_KEYS_HASH");
        });

        // ── AuditLogs ─────────────────────────────────────────────────────────
        modelBuilder.Entity<AuditLog>(e =>
        {
            e.ToTable("KV_AUDIT_LOG");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasColumnName("ID").UseIdentityColumn();
            e.Property(x => x.SecretId).HasColumnName("SECRET_ID");
            e.Property(x => x.Principal).HasColumnName("PRINCIPAL").HasMaxLength(300).IsRequired();
            e.Property(x => x.Action).HasColumnName("ACTION").HasMaxLength(50).IsRequired();
            e.Property(x => x.Detail).HasColumnName("DETAIL").HasMaxLength(2000);
            e.Property(x => x.IpAddress).HasColumnName("IP_ADDRESS").HasMaxLength(50);
            e.Property(x => x.Timestamp).HasColumnName("TIMESTAMP").IsRequired();
            e.HasOne(x => x.Secret).WithMany(s => s.AuditLogs).HasForeignKey(x => x.SecretId).OnDelete(DeleteBehavior.SetNull);
        });
    }
}
