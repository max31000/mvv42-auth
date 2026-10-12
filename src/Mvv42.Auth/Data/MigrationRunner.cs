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
        await using var conn = new MySqlConnection(ConnectionStringForMigrations(connectionString));
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

        foreach (var (fileName, sql) in EmbeddedMigrations())
        {
            if (applied.Contains(fileName))
                continue;

            logger.LogInformation("Applying migration {FileName}", fileName);
            await using var tx = await conn.BeginTransactionAsync();
            foreach (var statement in SplitSqlStatements(sql))
                await conn.ExecuteAsync(statement, transaction: tx);
            await conn.ExecuteAsync("INSERT INTO _migrations (FileName) VALUES (@fileName)", new { fileName }, tx);
            await tx.CommitAsync();
        }
    }

    /// <summary>Embedded <c>Data/Migrations/*.sql</c> in name order: ("001_init.sql", content).</summary>
    internal static IEnumerable<(string FileName, string Sql)> EmbeddedMigrations()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resources = assembly.GetManifestResourceNames()
            .Where(n => n.Contains(".Migrations.") && n.EndsWith(".sql", StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal);

        foreach (var resource in resources)
        {
            using var reader = new StreamReader(assembly.GetManifestResourceStream(resource)!);
            yield return (string.Join(".", resource.Split('.').TakeLast(2)), reader.ReadToEnd());
        }
    }

    /// <summary>
    /// Guarded ALTERs (003+) keep the statement in a session variable (<c>SET @ddl = IF(...)</c> → PREPARE/EXECUTE);
    /// MySqlConnector rejects unknown <c>@names</c> unless user variables are allowed.
    /// </summary>
    internal static string ConnectionStringForMigrations(string connectionString) =>
        new MySqlConnectionStringBuilder(connectionString) { AllowUserVariables = true }.ConnectionString;

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
