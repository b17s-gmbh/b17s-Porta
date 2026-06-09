# GraphQL Backend Support

The library supports calling GraphQL backends while exposing REST endpoints to clients. This is a common BFF pattern - REST facade over GraphQL.

## Basic Usage

```csharp
public class ProductTransformer : TransformerBase<ProductDto>
{
    private const string GetProductQuery = """
        query GetProduct($id: ID!) {
            product(id: $id) {
                id
                name
                slug
                featuredAsset { preview }
                variants { id name price }
            }
        }
        """;

    public override async Task<ProductDto> TransformAsync(TransformerContext context)
    {
        var productId = GetRouteValue(context, "id");

        // The configured backend (from ToGraphQL(...)) is exposed on the context
        // under the "BackendRequest" property.
        var backendRequest = (BackendRequest)context.Properties["BackendRequest"];

        // CallGraphQLAsync handles:
        // - Wrapping query + variables into { "query": "...", "variables": {...} }
        // - Unwrapping response from { "data": { "product": {...} } }
        // - Extracting errors from GraphQL errors array
        var result = await context.BackendCaller.CallGraphQLAsync<Product>(
            backendRequest,
            GetProductQuery,
            variables: new { id = productId },
            dataPath: "product",  // extracts data.product
            cancellationToken: context.CancellationToken
        );

        if (!result.IsSuccess)
        {
            // Surfaces the GraphQL-mapped status (404, 401, 403, ...) verbatim. Use this rather
            // than WriteBackendErrorResponseAsync for GraphQL results: an application-level auth
            // error (UNAUTHENTICATED/FORBIDDEN over HTTP 200) is the user's, and must reach the
            // client as 401/403 instead of the 502 the backend writer applies.
            await WriteGraphQLErrorResponseAsync(context, result);
            return default!;
        }

        return MapToDto(result.Data);
    }
}

// Endpoint registration - client sees REST
app.MapTransformer<ProductTransformer, ProductDto>()
    .FromGet("/api/products/{id}")
    .ToGraphQL($"{graphUrl}/my-api")  // GraphQL endpoint
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();
```

## Features

| Feature | Description |
|---------|-------------|
| `CallGraphQLAsync<T>()` | Wraps/unwraps GraphQL request/response |
| `ToGraphQL(url)` | Builder method for GraphQL backend (sets POST, content-type) |
| `dataPath` parameter | Extracts nested data (e.g., `"product"` → `data.product`) |
| Error handling | GraphQL errors array → `GraphQLResult.Error` |

## Error Handling

GraphQL returns HTTP 200 even with errors. The library handles this:

```csharp
// GraphQL response with errors
{
    "data": null,
    "errors": [
        { "message": "Product not found", "extensions": { "code": "NOT_FOUND" } }
    ]
}

// Becomes GraphQLResult with:
// - IsSuccess = false
// - MappedStatusCode = 404 (mapped from extensions.code)
// - Error = "Product not found" (the GraphQL error's message, verbatim)
```

### Error Code Mapping

| GraphQL Error Code | HTTP Status |
|-------------------|-------------|
| `NOT_FOUND` | 404 |
| `UNAUTHORIZED`, `UNAUTHENTICATED` | 401 |
| `FORBIDDEN`, `ACCESS_DENIED` | 403 |
| `BAD_REQUEST`, `VALIDATION_ERROR` | 400 |
| `INTERNAL_SERVER_ERROR` | 500 |
| `TIMEOUT`, `GATEWAY_TIMEOUT` | 504 |
| `TOO_MANY_REQUESTS` | 429 |

> **Relaying GraphQL errors:** use `WriteGraphQLErrorResponseAsync(context, result)` to surface
> these mapped statuses to the client. It relays the mapped status verbatim — including a genuine
> user-facing 401/403 from an application-level `UNAUTHENTICATED`/`FORBIDDEN` error — while masking
> 5xx detail. Do **not** route GraphQL results through `WriteBackendErrorResponseAsync`: that writer
> is for relayed *backend transport* statuses and remaps 401/403 to 502 (a BFF-credential failure),
> which would hide the documented GraphQL auth statuses. A transport-level backend 401/403 is
> already neutralized to 502 before it reaches your transformer.

## Parallel GraphQL Queries

```csharp
public class DashboardTransformer : TransformerBase<DashboardDto>
{
    public override async Task<DashboardDto> TransformAsync(TransformerContext context)
    {
        var backendRequest = (BackendRequest)context.Properties["BackendRequest"];

        // Parallel GraphQL queries
        var productsTask = context.BackendCaller.CallGraphQLAsync<List<Product>>(
            backendRequest,
            ProductsQuery, variables: null, dataPath: "products");
        var ordersTask = context.BackendCaller.CallGraphQLAsync<List<Order>>(
            backendRequest,
            OrdersQuery, variables: new { customerId = context.UserId }, dataPath: "orders");

        await Task.WhenAll(productsTask, ordersTask);

        return new DashboardDto
        {
            Products = productsTask.Result.Data,
            Orders = ordersTask.Result.Data
        };
    }
}
```

## Mutations

GraphQL mutations work the same way:

```csharp
public class CreateOrderTransformer : TransformerBase<CreateOrderRequest, OrderDto>
{
    private const string CreateOrderMutation = """
        mutation CreateOrder($input: CreateOrderInput!) {
            createOrder(input: $input) {
                id
                code
                state
                total
            }
        }
        """;

    public override async Task<OrderDto> TransformAsync(
        CreateOrderRequest? request,
        TransformerContext context)
    {
        var backendRequest = (BackendRequest)context.Properties["BackendRequest"];

        var result = await context.BackendCaller.CallGraphQLAsync<Order>(
            backendRequest,
            CreateOrderMutation,
            variables: new { input = request },
            dataPath: "createOrder",
            cancellationToken: context.CancellationToken
        );

        if (!result.IsSuccess)
        {
            await WriteGraphQLErrorResponseAsync(context, result);
            return default!;
        }

        return MapToDto(result.Data);
    }
}

// POST endpoint for mutation
app.MapTransformer<CreateOrderTransformer, CreateOrderRequest, OrderDto>()
    .FromPost("/api/orders")
    .ToGraphQL($"{graphUrl}/my-api")
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();
```
