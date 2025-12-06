// Streaming SSR demo page
// VULNERABILITY: Exposes Flight protocol streaming patterns

import { Suspense } from 'react';

// Component that streams chunks of data
async function StreamingChunk({ index, delay }: { index: number; delay: number }) {
  await new Promise((resolve) => setTimeout(resolve, delay));

  // Each chunk is sent via Flight protocol as it completes
  return (
    <div data-chunk-index={index}>
      <p>Chunk {index} loaded after {delay}ms</p>
      <p>Server timestamp: {Date.now()}</p>
      {/* Hidden data that gets serialized in Flight payload */}
      <input type="hidden" name={`chunk_${index}_data`} value={JSON.stringify({
        index,
        delay,
        timestamp: Date.now(),
        random: Math.random(),
      })} />
    </div>
  );
}

// Component that progressively reveals content
async function ProgressiveContent() {
  const chunks = [100, 300, 500, 700, 1000];

  return (
    <div>
      <h3>Progressive Content Loading</h3>
      {chunks.map((delay, index) => (
        <Suspense key={index} fallback={<div>Loading chunk {index}...</div>}>
          <StreamingChunk index={index} delay={delay} />
        </Suspense>
      ))}
    </div>
  );
}

// Large data streaming component
async function LargeDataStream() {
  await new Promise((resolve) => setTimeout(resolve, 200));

  // Generate large payload for Flight protocol testing
  const largeData = Array.from({ length: 100 }, (_, i) => ({
    id: i,
    name: `Item ${i}`,
    description: 'A'.repeat(100),
    nested: {
      field1: 'value1',
      field2: 'value2',
      array: [1, 2, 3, 4, 5],
    },
  }));

  return (
    <div>
      <h3>Large Data Stream</h3>
      <p>Streaming {largeData.length} items via Flight protocol...</p>
      {/* This creates a large Flight payload */}
      <pre style={{ maxHeight: '200px', overflow: 'auto' }}>
        {JSON.stringify(largeData, null, 2)}
      </pre>
    </div>
  );
}

// Nested streaming component
async function NestedStream({ depth }: { depth: number }) {
  await new Promise((resolve) => setTimeout(resolve, 100 * depth));

  if (depth <= 0) {
    return <div>Leaf node at depth 0</div>;
  }

  return (
    <div style={{ marginLeft: '1rem', borderLeft: '2px solid #ccc', paddingLeft: '1rem' }}>
      <p>Depth: {depth}</p>
      <Suspense fallback={<div>Loading depth {depth - 1}...</div>}>
        <NestedStream depth={depth - 1} />
      </Suspense>
    </div>
  );
}

export default async function StreamPage() {
  return (
    <div>
      <h1>Streaming SSR Demo</h1>
      <p>This page demonstrates React Flight streaming patterns that the scanner should detect.</p>

      <section>
        <h2>1. Progressive Content (Multiple Suspense Boundaries)</h2>
        <ProgressiveContent />
      </section>

      <section>
        <h2>2. Large Data Streaming</h2>
        <Suspense fallback={<div>Loading large dataset...</div>}>
          <LargeDataStream />
        </Suspense>
      </section>

      <section>
        <h2>3. Nested Streaming (5 levels deep)</h2>
        <Suspense fallback={<div>Loading nested content...</div>}>
          <NestedStream depth={5} />
        </Suspense>
      </section>

      {/* Server action that accepts streamed data */}
      <section>
        <h2>4. Action with Streaming Response</h2>
        <form action={async (formData: FormData) => {
          'use server';
          const data = Object.fromEntries(formData.entries());
          console.log('Streamed form data:', data);
          return { received: true, timestamp: Date.now() };
        }}>
          <textarea name="largeInput" placeholder="Enter large text to stream..." rows={5}></textarea>
          <button type="submit">Submit (Streams to Server)</button>
        </form>
      </section>
    </div>
  );
}
