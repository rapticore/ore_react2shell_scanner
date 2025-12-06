// Explicit RSC/Flight Protocol endpoint for testing
// This simulates raw Flight protocol responses

import { NextRequest, NextResponse } from 'next/server';

// Simulated Flight protocol chunks
const FLIGHT_CHUNKS = [
  '0:["$","div",null,{"children":"Hello from RSC"}]',
  '1:["$","p",null,{"children":"This is a paragraph"}]',
  '2:{"formState":["$undefined"]}',
  '3:["$","$ACTION_ID","submit_form"]',
];

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const chunk = searchParams.get('chunk');

  // Return specific chunk or all chunks
  const responseChunks = chunk
    ? FLIGHT_CHUNKS.slice(0, parseInt(chunk) + 1)
    : FLIGHT_CHUNKS;

  const body = responseChunks.join('\n');

  return new NextResponse(body, {
    headers: {
      'Content-Type': 'text/x-component',
      'X-NextJS-Cache': 'MISS',
      'X-Matched-Path': '/api/rsc',
      'RSC': '1',
      'Next-Router-State-Tree': '%5B%22%22%2C%7B%7D%5D',
      'Vary': 'RSC, Next-Router-State-Tree, Next-Router-Prefetch',
    },
  });
}

// Handle Flight protocol POST requests (server actions)
export async function POST(request: NextRequest) {
  const contentType = request.headers.get('content-type') || '';

  let body: string;
  if (contentType.includes('multipart/form-data')) {
    const formData = await request.formData();
    const entries = Object.fromEntries(formData.entries());
    body = JSON.stringify(entries);
  } else {
    body = await request.text();
  }

  // VULNERABILITY: Processing unsanitized input
  console.log('RSC POST body:', body);

  // Return Flight protocol response with action result
  const response = new NextResponse(
    `0:{"success":true,"input":${JSON.stringify(body)}}\n` +
    `1:["$","$ACTION_ID","action_complete"]\n` +
    `2:{"formState":["$Sreact.transition"]}`,
    {
      headers: {
        'Content-Type': 'text/x-component',
        'X-NextJS-Cache': 'MISS',
        'X-Action': 'process_action',
        'Next-Action': 'abcd1234',
      },
    }
  );

  return response;
}
