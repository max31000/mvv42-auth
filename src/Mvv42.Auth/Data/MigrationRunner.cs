using System.Reflection;
using Dapper;
using MySqlConnector;

namespace Mvv42.Auth.Data;

/// <summary>
/// Applies embedded <c>Data/Migrations/*.sql</c> in name order, recording them in <c>_migrations</c>
/// (same pattern as cashpulse/bonds). Note: MySQL commits DDL implicitly, the transaction only guards DML.
/// </summary>
public sealed class MigrationRunner(string connectionString, ILogger<MigrationRunner> logger)
{
    public async Task RunAsync()
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();

        await conn.ExecuteAsync("""
            CREATE TABLE IF NOT EXISTS _migrations (
                Id          INT           NOT NULL AUTO_INCREMENT,
                FileName    VARCHAR(255)  NOT NULL,
                AppliedAt   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (Id),
                UNIQUE KEY uq_migrations_filename (FileName)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """);

        var applied = (await conn.QueryAsync<string>("SELECT FileName FROM _migrations")).ToHashSet();

        var assembly = Assembly.GetExecutingAssembly();
        var resources = assembly.GetManifestResourceNames()
            .Where(n => n.Contains(".Migrations.") && n.EndsWith(".sql", StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal);

        foreach (var resource in resources)
        {
            var parts = resource.Split('.');
            var fileName = string.Join(".", parts.TakeLast(2)); // "001_init.sql"
            if (applied.Contains(fileName))
                continue;

            logger.LogInformation("Applying migration {FileName}", fileName);
            await using var stream = assembly.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            var sql = await reader.ReadToEndAsync();

            await using var tx = await conn.BeginTransactionAsync();
            foreach (var statement in SplitSqlStatements(sql))
                await conn.ExecuteAsync(statement, transaction: tx);
            await conn.ExecuteAsync("INSERT INTO _migrations (FileName) VALUES (@fileName)", new { fileName }, tx);
            await tx.CommitAsync();
        }
    }

    /// <summary>Strips <c>--</c> line comments and splits on <c>;</c> (no semicolons or "--" inside literals).</summary>
    internal static List<string> SplitSqlStatements(string sql)
    {
        var withoutComments = string.Join('\n', sql.Split('\n').Select(line =>
        {
            var idx = line.IndexOf("--", StringComparison.Ordinal);
            return idx < 0 ? line : line[..idx];
        }));

        return withoutComments.Split(';')
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();
    }
}
