// Main page - Server Component by default in Next.js 13+ App Router
// This demonstrates the base RSC pattern that the scanner should detect

import { Suspense } from 'react';
import { VulnerableUserData } from './components/VulnerableUserData';
import { VulnerableProductList } from './components/VulnerableProductList';
import { ServerActionForm } from './components/ServerActionForm';
import { DangerousHtmlRenderer } from './components/DangerousHtmlRenderer';

// Server Component - renders on the server and streams to client via Flight protocol
export default async function HomePage() {
  // Simulate async server-side data fetching
  const timestamp = new Date().toISOString();

  return (
    <div>
      <h1>Vulnerable RSC Test Application</h1>
      <p>Server rendered at: {timestamp}</p>

      <section>
        <h2>1. Basic Server Component (Flight Protocol)</h2>
        <p>This component streams via React Flight protocol.</p>
        <Suspense fallback={<div>Loading user data...</div>}>
          <VulnerableUserData userId="1" />
        </Suspense>
      </section>

      <section>
        <h2>2. Nested Server Components</h2>
        <Suspense fallback={<div>Loading products...</div>}>
          <VulnerableProductList />
        </Suspense>
      </section>

      <section>
        <h2>3. Server Actions (Form Submission)</h2>
        <ServerActionForm />
      </section>

      <section>
        <h2>4. Dangerous HTML Rendering</h2>
        <DangerousHtmlRenderer />
      </section>

      <section>
        <h2>Test Links</h2>
        <ul>
          <li><a href="/admin">Admin Panel (Protected Route)</a></li>
          <li><a href="/api/users">API: Users Endpoint</a></li>
          <li><a href="/api/products">API: Products Endpoint</a></li>
          <li><a href="/dashboard">Dashboard (Server Component)</a></li>
          <li><a href="/forms">Forms with Server Actions</a></li>
          <li><a href="/stream">Streaming SSR Demo</a></li>
        </ul>
      </section>
    </div>
  );
}
