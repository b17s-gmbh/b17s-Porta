namespace b17s.Porta.Tests;

/// <summary>
/// Serializes tests that are sensitive to the process-global Porta <see cref="System.Diagnostics.ActivitySource"/>.
/// </summary>
/// <remarks>
/// Some tests attach a global <see cref="System.Diagnostics.ActivityListener"/> to the shared Porta
/// ActivitySource, collect emitted spans into a (non-thread-safe) list, and assert on the exact count.
/// If any other test emits a Porta activity concurrently, that span lands in the listener's list -
/// corrupting both the enumeration and the count. Classes that either listen on the source or emit
/// activities through the real <c>BackendCaller</c> join this collection so xUnit never runs them in
/// parallel with one another.
/// </remarks>
[CollectionDefinition(Name)]
public sealed class PortaActivitySourceCollection
{
    public const string Name = "Porta ActivitySource";
}
