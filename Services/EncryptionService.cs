using System.Security.Cryptography;
using System.Text;

namespace KeyVaultService.Services;

/// <summary>
/// Encrypts secret values with a per-secret AES-256-GCM key.
/// The AES key itself is protected at rest using either Windows DPAPI (machine scope)
/// or a shared AES-256-GCM master key from configuration (for multi-instance deployments).
/// </summary>
public interface IEncryptionService
{
    (string encryptedValue, string protectedKey) Encrypt(string plaintext);
    string Decrypt(string encryptedValue, string protectedKey);
}

public class DpapiAesEncryptionService : IEncryptionService
{
    // Optional entropy makes DPAPI blobs non-transferable between deployments
    private static readonly byte[] s_entropy = Encoding.UTF8.GetBytes("KeyVaultService-v1");

    public (string encryptedValue, string protectedKey) Encrypt(string plaintext)
    {
        // 1. Generate a fresh random AES-256 key + nonce for this secret
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var nonce  = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize); // 12 bytes

        // 2. Encrypt the plaintext with AES-256-GCM
        var plaintextBytes  = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext      = new byte[plaintextBytes.Length];
        var tag             = new byte[AesGcm.TagByteSizes.MaxSize]; // 16 bytes

        using var aesGcm = new AesGcm(aesKey, AesGcm.TagByteSizes.MaxSize);
        aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // 3. Bundle: nonce(12) + tag(16) + ciphertext → Base64
        var bundle = new byte[nonce.Length + tag.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce,      0, bundle, 0,                          nonce.Length);
        Buffer.BlockCopy(tag,        0, bundle, nonce.Length,               tag.Length);
        Buffer.BlockCopy(ciphertext, 0, bundle, nonce.Length + tag.Length,  ciphertext.Length);

        var encryptedValue = Convert.ToBase64String(bundle);

        // 4. Protect the AES key with DPAPI (machine scope — survives IIS recycles)
        var protectedKeyBytes = ProtectedData.Protect(aesKey, s_entropy, DataProtectionScope.LocalMachine);
        var protectedKey      = Convert.ToBase64String(protectedKeyBytes);

        // Zero out key material
        CryptographicOperations.ZeroMemory(aesKey);

        return (encryptedValue, protectedKey);
    }

    public string Decrypt(string encryptedValue, string protectedKey)
    {
        // 1. Unprotect the AES key via DPAPI
        var protectedKeyBytes = Convert.FromBase64String(protectedKey);
        var aesKey            = ProtectedData.Unprotect(protectedKeyBytes, s_entropy, DataProtectionScope.LocalMachine);

        try
        {
            // 2. Unpack the bundle
            var bundle     = Convert.FromBase64String(encryptedValue);
            const int NonceLen = 12, TagLen = 16;

            var nonce      = bundle[..NonceLen];
            var tag        = bundle[NonceLen..(NonceLen + TagLen)];
            var ciphertext = bundle[(NonceLen + TagLen)..];
            var plaintext  = new byte[ciphertext.Length];

            // 3. Decrypt
            using var aesGcm = new AesGcm(aesKey, TagLen);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }
}

/// <summary>
/// Encrypts secret values with a per-secret AES-256-GCM key.
/// The per-secret key is itself wrapped using AES-256-GCM with a shared master key
/// read from configuration, making secrets portable across multiple instances
/// (e.g., behind a load balancer).
///
/// Configuration required:
///   Encryption:MasterKey — Base64-encoded 32-byte key
///                          Set via environment variable Encryption__MasterKey in production.
///
/// Generate a key:  openssl rand -base64 32
///
/// Security note: security of all secrets depends on keeping this master key secret.
/// Use an environment variable or secrets manager — never commit the key value.
/// </summary>
public sealed class AesKeyWrapEncryptionService : IEncryptionService
{
    private const int NonceLen = 12;
    private const int TagLen   = 16;

    private readonly byte[] _masterKey;

    public AesKeyWrapEncryptionService(IConfiguration configuration)
    {
        var raw = configuration["Encryption:MasterKey"]
            ?? throw new InvalidOperationException(
                "Encryption:MasterKey is required when Encryption:Mode is 'AesKeyWrap'. " +
                "Set it via the Encryption__MasterKey environment variable.");

        byte[] key;
        try { key = Convert.FromBase64String(raw); }
        catch (FormatException) { throw new InvalidOperationException("Encryption:MasterKey must be a valid Base64 string."); }

        if (key.Length != 32)
            throw new InvalidOperationException(
                $"Encryption:MasterKey must decode to exactly 32 bytes (got {key.Length}). " +
                "Generate one with: openssl rand -base64 32");

        _masterKey = key;
    }

    public (string encryptedValue, string protectedKey) Encrypt(string plaintext)
    {
        // 1. Generate a fresh random per-secret AES-256 key
        var perSecretKey = RandomNumberGenerator.GetBytes(32);

        try
        {
            // 2. Encrypt plaintext with the per-secret key
            var encryptedValue = AesGcmEncrypt(perSecretKey, Encoding.UTF8.GetBytes(plaintext));

            // 3. Wrap the per-secret key with the master key
            var protectedKey = AesGcmEncrypt(_masterKey, perSecretKey);

            return (encryptedValue, protectedKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(perSecretKey);
        }
    }

    public string Decrypt(string encryptedValue, string protectedKey)
    {
        // 1. Unwrap the per-secret key using the master key
        var perSecretKey = AesGcmDecrypt(_masterKey, protectedKey);

        try
        {
            // 2. Decrypt the secret value
            var plaintextBytes = AesGcmDecrypt(perSecretKey, encryptedValue);
            return Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(perSecretKey);
        }
    }

    // Encrypts data and returns Base64(nonce + tag + ciphertext)
    private static string AesGcmEncrypt(byte[] key, byte[] data)
    {
        var nonce      = RandomNumberGenerator.GetBytes(NonceLen);
        var ciphertext = new byte[data.Length];
        var tag        = new byte[TagLen];

        using var aesGcm = new AesGcm(key, TagLen);
        aesGcm.Encrypt(nonce, data, ciphertext, tag);

        var bundle = new byte[NonceLen + TagLen + ciphertext.Length];
        Buffer.BlockCopy(nonce,      0, bundle, 0,                    NonceLen);
        Buffer.BlockCopy(tag,        0, bundle, NonceLen,             TagLen);
        Buffer.BlockCopy(ciphertext, 0, bundle, NonceLen + TagLen,    ciphertext.Length);

        return Convert.ToBase64String(bundle);
    }

    // Decodes Base64(nonce + tag + ciphertext) and decrypts, returning plaintext bytes
    private static byte[] AesGcmDecrypt(byte[] key, string bundle64)
    {
        var bundle     = Convert.FromBase64String(bundle64);
        var nonce      = bundle[..NonceLen];
        var tag        = bundle[NonceLen..(NonceLen + TagLen)];
        var ciphertext = bundle[(NonceLen + TagLen)..];
        var plaintext  = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(key, TagLen);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}
