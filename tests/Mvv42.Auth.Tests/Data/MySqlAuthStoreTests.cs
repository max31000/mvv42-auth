using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Mvv42.Auth.Data;

namespace Mvv42.Auth.Tests.Data;

/// <summary>Theory skipped unless <c>MVV42_AUTH_TEST_MYSQL</c> holds a connection string to a test database.</summary>
public sealed class MySqlTheoryAttribute : TheoryAttribute
{
    public MySqlTheoryAttribute()
    {
        if (string.IsNullOrEmpty(MySqlStoreFixture.ConnectionString))
            Skip = "MVV42_AUTH_TEST_MYSQL is not set";
    }
}

public sealed class MySqlStoreFixture : IAsyncLifetime
{
    public static string? ConnectionString => Environment.GetEnvironmentVariable("MVV42_AUTH_TEST_MYSQL");

    public async Task InitializeAsync()
    {
        if (string.IsNullOrEmpty(ConnectionString))
            return;
        var runner = new MigrationRunner(ConnectionString, NullLogger<MigrationRunner>.Instance);
        await runner.RunAsync();
        await runner.RunAsync(); // second run must be a no-op
    }

    public Task DisposeAsync() => Task.CompletedTask;
}

/// <summary>
/// One fixture (migrations applied once) for every MySQL test class, and no parallelism between them: two fixtures
/// racing on the migration bookkeeping, or a re-applied DDL under a running contract test, would be flaky.
/// </summary>
[CollectionDefinition(Name)]
public sealed class MySqlCollection : ICollectionFixture<MySqlStoreFixture>
{
    public const string Name = "MySql";
}

/// <summary>
/// Runs every <see cref="AuthStoreContractTests"/> fact against MySQL (CI service container, see ci.yml).
/// Locally, without MySQL, the cases are reported as skipped.
/// </summary>
[Trait("Category", "MySql")]
[Collection(MySqlCollection.Name)]
public class MySqlAuthStoreTests
{
    // Private nested type: not discovered by xUnit itself, only invoked through the theory below.
    private sealed class MySqlContract : AuthStoreContractTests
    {
        protected override IAuthStore Store { get; } = new MySqlAuthStore(MySqlStoreFixture.ConnectionString!);
    }

    public static TheoryData<string> ContractCases()
    {
        var data = new TheoryData<string>();
        foreach (var method in typeof(AuthStoreContractTests).GetMethods().Where(m => m.IsDefined(typeof(FactAttribute))))
            data.Add(method.Name);
        return data;
    }

    [MySqlTheory]
    [MemberData(nameof(ContractCases))]
    public async Task Contract(string testName)
    {
        try
        {
            await (Task)typeof(AuthStoreContractTests).GetMethod(testName)!.Invoke(new MySqlContract(), null)!;
        }
        catch (TargetInvocationException e) when (e.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(e.InnerException);
        }
    }
}

/// <summary>Fact skipped unless <c>MVV42_AUTH_TEST_MYSQL</c> is set.</summary>
public sealed class MySqlFactAttribute : FactAttribute
{
    public MySqlFactAttribute()
    {
        if (string.IsNullOrEmpty(MySqlStoreFixture.ConnectionString))
            Skip = "MVV42_AUTH_TEST_MYSQL is not set";
    }
}

/// <summary>
/// MySQL commits DDL implicitly, so a crash between a migration's DDL and its <c>_migrations</c> row re-runs it:
/// every migration must apply cleanly on top of itself (spec §10.9).
/// </summary>
[Trait("Category", "MySql")]
[Collection(MySqlCollection.Name)]
public class MySqlMigrationTests
{
    [MySqlFact]
    public async Task EveryMigration_ReappliesOnTopOfItself_AndSchemaHasAdminColumnsAndIndexes()
    {
        await using var conn = new MySqlConnector.MySqlConnection(
            MigrationRunner.ConnectionStringForMigrations(MySqlStoreFixture.ConnectionString!));
        await conn.OpenAsync();

        foreach (var (_, sql) in MigrationRunner.EmbeddedMigrations())
            foreach (var statement in MigrationRunner.SplitSqlStatements(sql))
                await Dapper.SqlMapper.ExecuteAsync(conn, statement);

        async Task<long> Count(string sql, object args) => await Dapper.SqlMapper.ExecuteScalarAsync<long>(conn, sql, args);
        const string column = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = @table AND column_name = @name";
        Assert.Equal(1, await Count(column, new { table = "users", name = "is_blocked" }));
        Assert.Equal(1, await Count(column, new { table = "users", name = "blocked_at" }));
        Assert.Equal(1, await Count(column, new { table = "sessions", name = "ip" }));

        // 007/008 (closed registration) and 009 (code-first login), still right after being re-applied on top of themselves
        var appId = await Dapper.SqlMapper.QuerySingleAsync<(string Nullable, string Type, string Collation)>(conn, """
            SELECT is_nullable, column_type, collation_name FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = 'invites' AND column_name = 'app_id'
            """);
        Assert.Equal(("YES", "varchar(64)", "utf8mb4_unicode_ci"), appId);
        var result = await Dapper.SqlMapper.QuerySingleAsync<(string Nullable, string Type)>(conn, """
            SELECT is_nullable, column_type FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = 'login_events' AND column_name = 'result'
            """);
        Assert.Equal(("NO", "enum('ok','denied_blocked','invalid','replayed','denied_unregistered','invite_check_failed')"), result);
        // 007 keeps the invite → app foreign key (cascade on app delete/rename) on the now nullable column
        var fk = await Dapper.SqlMapper.QuerySingleAsync<(string Referenced, string OnDelete, string OnUpdate)>(conn, """
            SELECT referenced_table_name, delete_rule, update_rule FROM information_schema.referential_constraints
            WHERE constraint_schema = DATABASE() AND table_name = 'invites' AND constraint_name = 'fk_invites_app'
            """);
        Assert.Equal(("apps", "CASCADE", "CASCADE"), fk);
        Assert.Equal(["app_id"], await Dapper.SqlMapper.QueryAsync<string>(conn, """
            SELECT column_name FROM information_schema.key_column_usage
            WHERE table_schema = DATABASE() AND table_name = 'invites' AND constraint_name = 'fk_invites_app'
            """));

        var indexes = (await Dapper.SqlMapper.QueryAsync<(string Name, string Column, long Seq)>(conn, """
            SELECT index_name, column_name, seq_in_index FROM information_schema.statistics
            WHERE table_schema = DATABASE() AND table_name = 'login_events' ORDER BY index_name, seq_in_index
            """)).ToList();
        Assert.Equal(["at"], indexes.Where(i => i.Name == "ix_login_events_at").Select(i => i.Column));
        Assert.Equal(["user_id", "at"], indexes.Where(i => i.Name == "ix_login_events_user_at").Select(i => i.Column));
    }

    [MySqlFact]
    public async Task DeletingUser_NullsUserAndTelegramIdInLoginEvents()
    {
        var store = new MySqlAuthStore(MySqlStoreFixture.ConnectionString!);
        var tg = Random.Shared.NextInt64(1_000_000_000, 9_000_000_000);
        var user = await store.UpsertUserAsync(new Mvv42.Auth.Telegram.TelegramProfile(tg, "Gone", null, null, null), DateTime.UtcNow);
        var id = await store.AddLoginEventAsync(new LoginEvent { UserId = user.Id, TelegramId = tg, At = DateTime.UtcNow });

        await using var conn = new MySqlConnector.MySqlConnection(MySqlStoreFixture.ConnectionString!);
        await Dapper.SqlMapper.ExecuteAsync(conn, "DELETE FROM users WHERE id = @Id", new { user.Id });

        var e = (await store.ListLoginEventsAsync(null, id + 1, 1)).Single();
        Assert.Equal(id, e.Id);
        Assert.Null(e.UserId);
        Assert.Null(e.TelegramId);
    }
}

public class MySqlConnectionStringTests
{
    [Theory]
    [InlineData("Server=db;Database=mvv42_auth;User ID=u;Password=p")]
    [InlineData("Server=db;Database=mvv42_auth;User ID=u;Password=p;GuidFormat=Char36;UseAffectedRows=true")]
    public void Normalize_ReadsChar36AsString(string configured)
    {
        var normalized = new MySqlConnector.MySqlConnectionStringBuilder(MySqlAuthStore.Normalize(configured));
        Assert.Equal(MySqlConnector.MySqlGuidFormat.None, normalized.GuidFormat);
        Assert.Equal(MySqlConnector.MySqlDateTimeKind.Utc, normalized.DateTimeKind);
        Assert.Equal("mvv42_auth", normalized.Database);
    }
}
