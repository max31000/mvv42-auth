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
/// Runs every <see cref="AuthStoreContractTests"/> fact against MySQL (CI service container, see ci.yml).
/// Locally, without MySQL, the cases are reported as skipped.
/// </summary>
[Trait("Category", "MySql")]
public class MySqlAuthStoreTests : IClassFixture<MySqlStoreFixture>
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
