using b17s.Porta.Data;

using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Data;

/// <summary>
/// Verifies the model mapping of <see cref="DataProtectionDbContext"/>: the
/// Data Protection keys table name and schema must follow
/// <see cref="DataProtectionDbContextOptions"/> so that deployments sharing a
/// database can relocate the table without a code change, while existing
/// deployments keep the historical default table name (no migration).
/// </summary>
public class DataProtectionDbContextTests
{
    private static DataProtectionDbContext CreateContext(DataProtectionDbContextOptions? tableOptions = null)
    {
        // EF caches the model per context type, but this context's model depends on
        // the injected table options. A fresh internal service provider per context
        // keeps each test's model isolated from the others' cached model.
        var options = new DbContextOptionsBuilder<DataProtectionDbContext>()
            .UseInMemoryDatabase(nameof(DataProtectionDbContextTests))
            .EnableServiceProviderCaching(false)
            .Options;

        return new DataProtectionDbContext(
            options,
            tableOptions is null ? null : Options.Create(tableOptions));
    }

    [Fact]
    public void WithoutTableOptions_MapsToDefaultTableNameWithoutSchema()
    {
        using var context = CreateContext();

        var entity = context.Model.FindEntityType(typeof(DataProtectionKey));

        Assert.NotNull(entity);
        Assert.Equal(DataProtectionDbContextOptions.DefaultTableName, entity.GetTableName());
        Assert.Null(entity.GetSchema());
    }

    [Fact]
    public void CustomTableName_IsApplied()
    {
        using var context = CreateContext(new DataProtectionDbContextOptions
        {
            TableName = "PortaKeys",
        });

        var entity = context.Model.FindEntityType(typeof(DataProtectionKey));

        Assert.NotNull(entity);
        Assert.Equal("PortaKeys", entity.GetTableName());
        Assert.Null(entity.GetSchema());
    }

    [Fact]
    public void CustomSchema_IsApplied()
    {
        using var context = CreateContext(new DataProtectionDbContextOptions
        {
            TableName = "Keys",
            Schema = "porta",
        });

        var entity = context.Model.FindEntityType(typeof(DataProtectionKey));

        Assert.NotNull(entity);
        Assert.Equal("Keys", entity.GetTableName());
        Assert.Equal("porta", entity.GetSchema());
    }

    [Fact]
    public void EmptySchema_FallsBackToProviderDefault()
    {
        // Empty string must behave like null (provider default schema), not become
        // a literal empty-string schema in the mapping.
        using var context = CreateContext(new DataProtectionDbContextOptions
        {
            Schema = string.Empty,
        });

        var entity = context.Model.FindEntityType(typeof(DataProtectionKey));

        Assert.NotNull(entity);
        Assert.Equal(DataProtectionDbContextOptions.DefaultTableName, entity.GetTableName());
        Assert.Null(entity.GetSchema());
    }

    [Fact]
    public void PrimaryKey_IsId()
    {
        using var context = CreateContext();

        var key = context.Model.FindEntityType(typeof(DataProtectionKey))?.FindPrimaryKey();

        Assert.NotNull(key);
        var property = Assert.Single(key.Properties);
        Assert.Equal(nameof(DataProtectionKey.Id), property.Name);
    }

    [Fact]
    public void DataProtectionKeys_RoundTripsThroughTheKeyContextInterface()
    {
        // The Data Protection EF repository talks to the context exclusively via
        // IDataProtectionKeyContext.DataProtectionKeys - exercise that path.
        using var context = CreateContext();
        IDataProtectionKeyContext keyContext = context;

        keyContext.DataProtectionKeys.Add(new DataProtectionKey
        {
            FriendlyName = "key-1",
            Xml = "<key id=\"1\" />",
        });
        context.SaveChanges();

        var stored = Assert.Single(keyContext.DataProtectionKeys.AsNoTracking());
        Assert.Equal("key-1", stored.FriendlyName);
        Assert.Equal("<key id=\"1\" />", stored.Xml);
    }
}
