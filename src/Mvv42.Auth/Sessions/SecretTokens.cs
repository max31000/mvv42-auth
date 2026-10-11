using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Mvv42.Auth.Sessions;

/// <summary>Opaque random tokens (refresh tokens, invite codes); only their SHA-256 is stored.</summary>
public static class SecretTokens
{
    public static string New(int bytes = 32) => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(bytes));

    public static string Sha256Hex(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
}
