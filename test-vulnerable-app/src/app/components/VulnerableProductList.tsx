// Server Component that fetches and displays products
// VULNERABILITY: Demonstrates multiple RSC vulnerability patterns

interface Product {
  id: string;
  name: string;
  price: number;
  description: string;
}

// Simulated product database
const products: Product[] = [
  { id: '1', name: 'Widget A', price: 29.99, description: '<script>alert("xss")</script>Widget description' },
  { id: '2', name: 'Widget B', price: 49.99, description: 'Another widget<img src=x onerror=alert("xss")>' },
  { id: '3', name: 'Widget C', price: 99.99, description: 'Premium widget with extra features' },
];

// VULNERABILITY: No sanitization of product data
async function fetchProducts(): Promise<Product[]> {
  // Simulate async database call
  await new Promise((resolve) => setTimeout(resolve, 150));
  return products;
}

// VULNERABILITY: Nested server component with unsanitized data
async function ProductCard({ product }: { product: Product }) {
  // This nested server component increases attack surface
  return (
    <div className="product-card" data-product-id={product.id}>
      <h4>{product.name}</h4>
      <p className="price">${product.price.toFixed(2)}</p>
      {/* VULNERABILITY: Dangerous HTML rendering */}
      <div
        className="description"
        dangerouslySetInnerHTML={{ __html: product.description }}
      />
      {/* VULNERABILITY: Hidden data exposed in Flight payload */}
      <input type="hidden" name="product_data" value={JSON.stringify(product)} />
    </div>
  );
}

export async function VulnerableProductList() {
  const productList = await fetchProducts();

  return (
    <div className="product-list">
      <h3>Products (Fetched on Server)</h3>
      {/* VULNERABILITY: Each product card is a nested server component */}
      {productList.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
      {/* VULNERABILITY: Exposing product count and metadata */}
      <script
        id="product-metadata"
        type="application/json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            count: productList.length,
            fetchedAt: new Date().toISOString(),
            serverInfo: process.env.NODE_ENV,
          }),
        }}
      />
    </div>
  );
}
