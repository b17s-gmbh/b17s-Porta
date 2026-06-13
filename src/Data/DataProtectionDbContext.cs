using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Data;

/// <summary>
/// DbContext for storing ASP.NET Core Data Protection keys in a relational store.
/// Keys are used to encrypt session tickets and refresh tokens at rest.
///
/// Table name and schema are configurable via <see cref="DataProtectionDbContextOptions"/>.
/// Defaults are <see cref="DataProtectionDbContextOptions.DefaultTableName"/> with no
/// explicit schema (provider default). Override these in shared / multi-tenant
/// databases to avoid collisions with other apps that store DP keys in the same
/// database.
/// </summary>
public sealed class DataProtectionDbContext : DbContext, IDataProtectionKeyContext
{
    private readonly DataProtectionDbContextOptions _tableOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="DataProtectionDbContext"/> class.
    /// </summary>
    /// <param name="options">The EF Core options used to configure the context (provider, connection, etc.).</param>
    /// <param name="tableOptions">
    /// Optional table/schema configuration for the Data Protection keys table. When
    /// <see langword="null"/>, the defaults on <see cref="DataProtectionDbContextOptions"/> are used.
    /// </param>
    public DataProtectionDbContext(
        DbContextOptions<DataProtectionDbContext> options,
        IOptions<DataProtectionDbContextOptions>? tableOptions = null)
        : base(options)
    {
        _tableOptions = tableOptions?.Value ?? new DataProtectionDbContextOptions();
    }

    /// <summary>
    /// Data Protection keys table.
    /// </summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    /// <inheritdoc/>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<DataProtectionKey>(entity =>
        {
            if (string.IsNullOrEmpty(_tableOptions.Schema))
            {
                entity.ToTable(_tableOptions.TableName);
            }
            else
            {
                entity.ToTable(_tableOptions.TableName, _tableOptions.Schema);
            }
            entity.HasKey(k => k.Id);
        });
    }
}

/// <summary>
/// Configuration for the table that backs <see cref="DataProtectionDbContext"/>.
/// Set via <c>services.Configure&lt;DataProtectionDbContextOptions&gt;(...)</c> or
/// through the parameters on
/// <c>AddPortaDataProtectionWithEntityFrameworkStore</c>.
/// </summary>
public sealed class DataProtectionDbContextOptions
{
    /// <summary>
    /// Default unqualified table name when no override is supplied. Kept
    /// stable so existing deployments don't need a migration after this
    /// configuration knob was introduced.
    /// </summary>
    public const string DefaultTableName = "DataProtectionKeys";

    /// <summary>
    /// Name of the table that stores Data Protection keys. Defaults to
    /// <see cref="DefaultTableName"/>.
    /// </summary>
    public string TableName { get; set; } = DefaultTableName;

    /// <summary>
    /// Optional schema for the Data Protection keys table. Leave null/empty to
    /// fall back to the EF Core provider's default schema (e.g. <c>public</c>
    /// for PostgreSQL, <c>dbo</c> for SQL Server).
    /// </summary>
    public string? Schema { get; set; }
}
