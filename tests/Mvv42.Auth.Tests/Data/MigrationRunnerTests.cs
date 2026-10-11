using System.Reflection;
using Mvv42.Auth.Data;

namespace Mvv42.Auth.Tests.Data;

public class MigrationRunnerTests
{
    [Fact]
    public void SplitSqlStatements_DropsCommentsAndEmptyStatements()
    {
        var statements = MigrationRunner.SplitSqlStatements("""
            -- header; with a semicolon
            CREATE TABLE a (id INT); -- trailing
            ;
            INSERT INTO a VALUES (1);
            """);

        Assert.Equal(["CREATE TABLE a (id INT)", "INSERT INTO a VALUES (1)"], statements);
    }

    [Fact]
    public void InitMigration_IsEmbedded_AndCreatesAllTables()
    {
        var assembly = typeof(MigrationRunner).Assembly;
        var name = Assert.Single(assembly.GetManifestResourceNames(), n => n.EndsWith(".Migrations.001_init.sql"));
        using var reader = new StreamReader(assembly.GetManifestResourceStream(name)!);
        var statements = MigrationRunner.SplitSqlStatements(reader.ReadToEnd());

        foreach (var table in new[] { "users", "apps", "app_grants", "invites", "sessions" })
            Assert.Contains(statements, s => s.StartsWith($"CREATE TABLE IF NOT EXISTS {table} ("));
        Assert.Contains(statements, s => s.StartsWith("INSERT IGNORE INTO apps"));
    }

    public static TheoryData<string> Migrations()
    {
        var data = new TheoryData<string>();
        foreach (var name in typeof(MigrationRunner).Assembly.GetManifestResourceNames().Where(n => n.Contains(".Migrations.")))
            data.Add(name);
        return data;
    }

    [Fact]
    public void RefreshTokenHistoryMigration_IsEmbedded()
    {
        Assert.Contains(Migrations(), row => ((string)row[0]).EndsWith(".Migrations.002_refresh_token_history.sql"));
    }

    /// <summary>MySQL commits DDL implicitly: a migration that failed halfway must be re-runnable.</summary>
    [Theory]
    [MemberData(nameof(Migrations))]
    public void Migrations_AreIdempotent(string resource)
    {
        using var reader = new StreamReader(typeof(MigrationRunner).Assembly.GetManifestResourceStream(resource)!);
        foreach (var statement in MigrationRunner.SplitSqlStatements(reader.ReadToEnd()))
        {
            if (statement.StartsWith("CREATE TABLE", StringComparison.OrdinalIgnoreCase))
                Assert.StartsWith("CREATE TABLE IF NOT EXISTS ", statement, StringComparison.OrdinalIgnoreCase);
            else if (statement.StartsWith("INSERT", StringComparison.OrdinalIgnoreCase))
                Assert.StartsWith("INSERT IGNORE ", statement, StringComparison.OrdinalIgnoreCase);
            else
                Assert.Fail($"Unexpected statement kind (make it idempotent and extend this test): {statement[..Math.Min(60, statement.Length)]}");
        }
    }
}
