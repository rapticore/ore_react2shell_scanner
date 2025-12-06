// Server Action endpoint simulation
// VULNERABILITY: Exposes action invocation patterns

import { NextRequest, NextResponse } from 'next/server';

// Simulated action handlers
const actions: Record<string, (data: unknown) => unknown> = {
  'create_user': (data) => ({ created: true, user: data }),
  'update_user': (data) => ({ updated: true, user: data }),
  'delete_user': (data) => ({ deleted: true, id: data }),
  'execute_command': (data) => {
    // VULNERABILITY: Command execution simulation
    console.log('Executing command:', data);
    return { executed: true, command: data };
  },
  'query_database': (data) => {
    // VULNERABILITY: SQL injection simulation
    console.log('Database query:', data);
    return { results: [], query: data };
  },
};

export async function POST(request: NextRequest) {
  // Check for action header
  const actionId = request.headers.get('Next-Action') ||
    request.headers.get('X-Action') ||
    'default';

  let data: unknown;
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('multipart/form-data')) {
    const formData = await request.formData();
    data = Object.fromEntries(formData.entries());
  } else if (contentType.includes('application/json')) {
    data = await request.json();
  } else {
    data = await request.text();
  }

  // VULNERABILITY: Direct action execution without validation
  console.log(`Action ${actionId} invoked with:`, data);

  const handler = actions[actionId] || ((d) => ({ action: actionId, data: d }));
  const result = handler(data);

  // Return Flight protocol formatted response
  return new NextResponse(
    `0:${JSON.stringify(result)}\n` +
    `1:["$","$ACTION_ID","${actionId}"]\n` +
    `2:{"formState":["$Sreact.transition"]}`,
    {
      headers: {
        'Content-Type': 'text/x-component',
        'Next-Action': actionId,
        'X-Action': actionId,
        '$ACTION_ID': actionId,
      },
    }
  );
}

export async function GET(request: NextRequest) {
  // Return available actions (information disclosure)
  return new NextResponse(
    `0:${JSON.stringify({ actions: Object.keys(actions) })}\n` +
    `1:["$","div",null,{"children":"Available actions"}]`,
    {
      headers: {
        'Content-Type': 'text/x-component',
        'X-NextJS-Cache': 'MISS',
      },
    }
  );
}
