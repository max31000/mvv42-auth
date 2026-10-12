using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Mvv42.Auth.Sessions;

namespace Mvv42.Auth.Invites;

/// <summary>
/// Hashes invite codes. New codes are stored as <c>HMAC-SHA256(pepper, normalised code)</c>; the 32-byte pepper lives in
/// <c>KeysPath/invite-pepper</c> next to the signing keys and is created on first start (atomically, mode 0600), so a
/// leaked <c>invites</c> table alone does not allow brute-forcing the 60-bit codes. Codes created before that were
/// stored as <c>SHA-256(raw code)</c>, which stays a lookup fallback.
/// </summary>
public sealed class InviteCodeHasher
{
    public const string PepperFileName = "invite-pepper";
    private const int PepperLength = 32;

    private readonly byte[] _pepper;

    /// <exception cref="InvalidOperationException">The pepper file exists but is not exactly 32 bytes.</exception>
    public InviteCodeHasher(string keysPath, ILogger? logger = null)
    {
        var path = Path.Combine(keysPath, PepperFileName);
        if (!File.Exists(path) && Create(keysPath, path, logger ?? NullLogger.Instance))
            (logger ?? NullLogger.Instance).LogWarning(
                "Created a new invite pepper {Path}: invite codes issued with any previous pepper can no longer be found", path);

        _pepper = File.ReadAllBytes(path);
        if (_pepper.Length != PepperLength)
            throw new InvalidOperationException($"{path}: the invite pepper must be exactly {PepperLength} bytes, found {_pepper.Length}.");
    }

    /// <summary>Hex HMAC-SHA256 of a normalised code (how new codes are stored).</summary>
    public string Hash(string normalizedCode) =>
        Convert.ToHexString(HMACSHA256.HashData(_pepper, Encoding.UTF8.GetBytes(normalizedCode))).ToLowerInvariant();

    /// <summary>
    /// Stored hashes the code may have, in lookup order: HMAC of the normalised code (new format), then legacy SHA-256 of
    /// the trimmed raw input — only when that raw input itself looks like a legacy code.
    /// </summary>
    public IReadOnlyList<string> Candidates(InviteCode code)
    {
        var candidates = new List<string>(2);
        if (code.Kind == InviteCodeKind.Normalized)
            candidates.Add(Hash(code.Value));
        if (InviteCodes.LooksLegacy(code.Raw))
            candidates.Add(SecretTokens.Sha256Hex(code.Raw));
        return candidates;
    }

    /// <summary>
    /// Same pattern as the signing keys: write <c>*.tmp</c> (0600), fsync, rename, then fsync the directory (Linux) so
    /// the rename survives a crash. A lost race keeps the winner's file. true = this call created the file.
    /// </summary>
    private static bool Create(string keysPath, string path, ILogger logger)
    {
        Directory.CreateDirectory(keysPath);
        var tmp = $"{path}.{Guid.NewGuid():N}.tmp";
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(tmp, options))
        {
            stream.Write(RandomNumberGenerator.GetBytes(PepperLength));
            stream.Flush(flushToDisk: true);
        }

        try
        {
            File.Move(tmp, path, overwrite: false);
        }
        catch (IOException) when (File.Exists(path))
        {
            File.Delete(tmp); // another process created it first: use theirs
            return false;
        }

        if (OperatingSystem.IsLinux() && !SyncDirectory(keysPath))
            logger.LogWarning("Could not fsync {Directory} after creating the invite pepper (errno {Errno})",
                keysPath, Marshal.GetLastPInvokeError());
        return true;
    }

    /// <summary>fsync of a directory (makes a rename in it durable). Linux only; false elsewhere or on failure.</summary>
    internal static bool SyncDirectory(string directory)
    {
        if (!OperatingSystem.IsLinux())
            return false;
        var fd = Open(directory, 0 /* O_RDONLY */);
        if (fd < 0)
            return false;
        try
        {
            return Fsync(fd) == 0;
        }
        finally
        {
            _ = Close(fd);
        }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int fd);
}
