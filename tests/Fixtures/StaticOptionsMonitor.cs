using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Fixtures;

/// <summary>
/// Fixed-value <see cref="IOptionsMonitor{T}"/> for services that read
/// <c>CurrentValue</c> per call (reload-aware singletons) in tests that
/// don't exercise reload behavior.
/// </summary>
public sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T> where T : class
{
    public T CurrentValue => value;
    public T Get(string? name) => value;
    public IDisposable? OnChange(Action<T, string?> listener) => null;
}
