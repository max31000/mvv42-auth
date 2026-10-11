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
            Assert.Contains(statements, s => s.StartsWith($"CREATE TABLE {table} ("));
        Assert.Contains(statements, s => s.StartsWith("INSERT INTO apps"));
    }
}
