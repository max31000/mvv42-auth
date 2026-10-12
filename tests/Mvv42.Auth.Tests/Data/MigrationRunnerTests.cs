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
            else if (statement.StartsWith("SET @ddl", StringComparison.OrdinalIgnoreCase))
            {
                // Guarded ALTER: runs only when information_schema says the change is not there yet, else DO 0.
                Assert.Contains("information_schema.", statement, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("table_schema = DATABASE()", statement, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("'DO 0'", statement, StringComparison.Ordinal);
            }
            else if (statement is "PREPARE mvv42_ddl FROM @ddl" or "EXECUTE mvv42_ddl" or "DEALLOCATE PREPARE mvv42_ddl")
            {
            }
            else
                Assert.Fail($"Unexpected statement kind (make it idempotent and extend this test): {statement[..Math.Min(60, statement.Length)]}");
        }
    }

    private static string ReadMigration(string fileName)
    {
        var assembly = typeof(MigrationRunner).Assembly;
        var name = Assert.Single(assembly.GetManifestResourceNames(), n => n.EndsWith(".Migrations." + fileName));
        using var reader = new StreamReader(assembly.GetManifestResourceStream(name)!);
        return reader.ReadToEnd();
    }

    /// <summary>Spec §10.9: one schema change per file (so a crash between DDL and bookkeeping can only leave one).</summary>
    [Theory]
    [InlineData("003_users_blocked.sql", "ALTER TABLE users ADD COLUMN is_blocked")]
    [InlineData("004_users_blocked_at.sql", "ALTER TABLE users ADD COLUMN blocked_at")]
    [InlineData("005_sessions_ip.sql", "ALTER TABLE sessions ADD COLUMN ip")]
    [InlineData("006_login_events.sql", "CREATE TABLE IF NOT EXISTS login_events (")]
    [InlineData("007_invites_app_nullable.sql", "ALTER TABLE invites MODIFY app_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL")]
    [InlineData("008_login_events_unregistered.sql", "ALTER TABLE login_events MODIFY result ENUM(''ok'',''denied_blocked'',''invalid'',''replayed'',''denied_unregistered'') NOT NULL")]
    public void AdminMigrations_OneSchemaChangeEach(string fileName, string change)
    {
        var sql = string.Join('\n', MigrationRunner.SplitSqlStatements(ReadMigration(fileName)));
        Assert.Contains(change, sql, StringComparison.Ordinal);
        var ddl = System.Text.RegularExpressions.Regex.Matches(sql, @"\b(ALTER TABLE|CREATE TABLE)\b").Count;
        Assert.Equal(1, ddl);
    }

    [Fact]
    public void LoginEvents_HasIndexesOnAt_AndUserIdAt()
    {
        var sql = ReadMigration("006_login_events.sql");
        Assert.Contains("KEY ix_login_events_at (at)", sql, StringComparison.Ordinal);
        Assert.Contains("KEY ix_login_events_user_at (user_id, at)", sql, StringComparison.Ordinal);
        Assert.Contains("ENUM('ok','denied_blocked','invalid','replayed')", sql, StringComparison.Ordinal);
    }

    /// <summary>Closed registration, review decision 11: the guards that make 007/008 re-runnable.</summary>
    [Theory]
    [InlineData("007_invites_app_nullable.sql", "table_name = 'invites' AND column_name = 'app_id' AND is_nullable = 'NO'")]
    [InlineData("008_login_events_unregistered.sql", "table_name = 'login_events' AND column_name = 'result' AND column_type NOT LIKE '%denied_unregistered%'")]
    public void ClosedRegistrationMigrations_AreGuarded(string fileName, string guard)
    {
        var statement = Assert.Single(MigrationRunner.SplitSqlStatements(ReadMigration(fileName)), s => s.StartsWith("SET @ddl", StringComparison.Ordinal));
        Assert.Contains(guard, statement, StringComparison.Ordinal);
        // The guard counts rows that still need the change: > 0 → run the ALTER, else DO 0.
        Assert.Matches(@"\) > 0, 'ALTER TABLE [^']*(''[^']*)*', 'DO 0'\)$", statement);
    }

    [Fact]
    public void MigrationConnection_AllowsUserVariables_ForGuardedDdl()
    {
        var cs = new MySqlConnector.MySqlConnectionStringBuilder(
            MigrationRunner.ConnectionStringForMigrations("Server=db;Database=x;User ID=u;Password=p"));
        Assert.True(cs.AllowUserVariables);
    }
}
