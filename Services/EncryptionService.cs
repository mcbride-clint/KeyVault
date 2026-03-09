using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KeyVaultService.Services;

/// <summary>
/// Encrypts secret values with a per-secret AES-256-GCM key.
/// The AES key itself is protected at rest using Windows DPAPI (machine scope),
/// which ties it to the IIS host machine / service account.
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
