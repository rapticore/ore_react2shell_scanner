// Middleware - adds RSC-related headers to all responses
// This helps the scanner detect RSC patterns

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Get the response
  const response = NextResponse.next();

  // Add RSC-related headers for scanner detection
  response.headers.set('X-NextJS-Cache', 'MISS');
  response.headers.set('X-Powered-By', 'Next.js');
  response.headers.set('X-Matched-Path', request.nextUrl.pathname);

  // If RSC header is present, add more indicators
  if (request.headers.get('RSC') === '1') {
    response.headers.set('RSC', '1');
    response.headers.set('Vary', 'RSC, Next-Router-State-Tree, Next-Router-Prefetch');
  }

  // If Next-Router headers are present
  if (request.headers.get('Next-Router-Prefetch')) {
    response.headers.set('Next-Router-Prefetch', '1');
  }

  // Add middleware rewrite header for detection
  if (request.nextUrl.pathname.startsWith('/_rsc')) {
    response.headers.set('X-Middleware-Rewrite', '/');
  }

  return response;
}

// Apply middleware to all routes
export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
