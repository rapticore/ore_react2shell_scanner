// Dashboard - Server Component with streaming and suspense
// VULNERABILITY: Multiple RSC patterns for scanner detection

import { Suspense } from 'react';

// Simulated slow data fetching
async function SlowDataComponent() {
  await new Promise((resolve) => setTimeout(resolve, 2000));

  return (
    <div>
      <h3>Slow Data Loaded</h3>
      <p>This data took 2 seconds to load on the server.</p>
      {/* VULNERABILITY: Server-side timestamp exposed */}
      <p>Server time: {new Date().toISOString()}</p>
    </div>
  );
}

// Another async component
async function UserStats() {
  await new Promise((resolve) => setTimeout(resolve, 500));

  const stats = {
    totalUsers: 1234,
    activeUsers: 567,
    revenue: '$45,678',
    // VULNERABILITY: Exposing sensitive metrics
    secretApiKey: 'sk_live_xxxxxxxxxxxx',
    databaseUrl: 'postgres://user:pass@localhost:5432/db',
  };

  return (
    <div>
      <h3>User Statistics</h3>
      <pre>{JSON.stringify(stats, null, 2)}</pre>
    </div>
  );
}

// Component with form state
async function DashboardActions() {
  async function saveSettings(formData: FormData) {
    'use server';
    const settings = Object.fromEntries(formData.entries());
    console.log('Dashboard settings:', settings);
    return { saved: true, settings };
  }

  async function exportData(formData: FormData) {
    'use server';
    const format = formData.get('format') as string;
    const query = formData.get('query') as string;
    // VULNERABILITY: User-controlled query in export
    console.log(`Exporting data: format=${format}, query=${query}`);
    return { exported: true, format, query };
  }

  return (
    <div>
      <h3>Dashboard Actions</h3>
      <form action={saveSettings}>
        <input type="text" name="theme" placeholder="Theme" defaultValue="dark" />
        <input type="text" name="language" placeholder="Language" defaultValue="en" />
        <button type="submit">Save Settings</button>
      </form>

      <form action={exportData}>
        <select name="format">
          <option value="csv">CSV</option>
          <option value="json">JSON</option>
          <option value="xml">XML</option>
        </select>
        <input
          type="text"
          name="query"
          placeholder="Export query"
          defaultValue="SELECT * FROM users"
        />
        <button type="submit">Export</button>
      </form>
    </div>
  );
}

export default async function DashboardPage() {
  return (
    <div>
      <h1>Dashboard</h1>
      <p>This page demonstrates streaming RSC with Suspense boundaries.</p>

      {/* Multiple Suspense boundaries create multiple Flight streams */}
      <section>
        <h2>Stats (streams with delay)</h2>
        <Suspense fallback={<div>Loading stats...</div>}>
          <UserStats />
        </Suspense>
      </section>

      <section>
        <h2>Slow Data (2s delay)</h2>
        <Suspense fallback={<div>Loading slow data...</div>}>
          <SlowDataComponent />
        </Suspense>
      </section>

      <section>
        <h2>Actions</h2>
        <Suspense fallback={<div>Loading actions...</div>}>
          <DashboardActions />
        </Suspense>
      </section>
    </div>
  );
}
