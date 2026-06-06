namespace b17s.Porta.Transformers;

/// <summary>
/// Marks a raw-forward transformer type as requiring an authenticated user.
/// Read at endpoint-build time without instantiating the transformer, so it is
/// safe to use on transformers with scoped or HttpContext-bound dependencies.
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
public sealed class RequiresAuthenticationAttribute : Attribute
{
}
