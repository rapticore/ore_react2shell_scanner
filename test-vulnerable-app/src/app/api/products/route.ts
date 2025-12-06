// API Route - Products endpoint with RSC-like response patterns

import { NextRequest, NextResponse } from 'next/server';

const products = [
  { id: 1, name: 'Widget A', price: 29.99, stock: 100 },
  { id: 2, name: 'Widget B', price: 49.99, stock: 50 },
  { id: 3, name: 'Widget C', price: 99.99, stock: 25 },
];

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const format = searchParams.get('format');

  // Check for RSC-specific headers
  const rscHeader = request.headers.get('RSC');
  const nextRouterState = request.headers.get('Next-Router-State-Tree');

  // If RSC headers present, respond with Flight-like format
  if (rscHeader === '1' || nextRouterState) {
    // Simulate Flight protocol response
    const flightResponse = products.map((p, i) =>
      `${i}:${JSON.stringify(p)}`
    ).join('\n');

    return new NextResponse(flightResponse, {
      headers: {
        'Content-Type': 'text/x-component',
        'X-NextJS-Cache': 'HIT',
        'X-Matched-Path': '/api/products',
      },
    });
  }

  // Standard JSON response with Next.js indicators
  const response = NextResponse.json(products);
  response.headers.set('X-Powered-By', 'Next.js');
  response.headers.set('X-NextJS-Cache', 'MISS');
  return response;
}

export async function POST(request: NextRequest) {
  const body = await request.json();

  const newProduct = {
    id: products.length + 1,
    ...body,
  };

  products.push(newProduct);

  // Return Flight-like response for RSC compatibility
  const response = new NextResponse(
    `0:${JSON.stringify({ success: true, product: newProduct })}`,
    {
      status: 201,
      headers: {
        'Content-Type': 'text/x-component',
        'X-NextJS-Cache': 'MISS',
      },
    }
  );

  return response;
}
