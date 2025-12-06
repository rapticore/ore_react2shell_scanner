import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Vulnerable RSC Test App',
  description: 'Test application for RSC vulnerability scanning',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <header style={{ padding: '1rem', background: '#ff4444', color: 'white' }}>
          <strong>WARNING: This is a vulnerable test application. Do not deploy to production.</strong>
        </header>
        <main style={{ padding: '2rem' }}>
          {children}
        </main>
      </body>
    </html>
  );
}
