// API Route - Users endpoint
// This simulates a traditional API that might coexist with RSC

import { NextRequest, NextResponse } from 'next/server';

const users = [
  { id: 1, name: 'Admin', email: 'admin@test.com', role: 'admin' },
  { id: 2, name: 'User', email: 'user@test.com', role: 'user' },
  { id: 3, name: 'Guest', email: 'guest@test.com', role: 'guest' },
];

// VULNERABILITY: No authentication on user list
export async function GET(request: NextRequest) {
  // Add headers that indicate RSC framework
  const response = NextResponse.json(users);
  response.headers.set('X-Powered-By', 'Next.js');
  response.headers.set('X-NextJS-Cache', 'MISS');
  return response;
}

// VULNERABILITY: Mass assignment vulnerability
export async function POST(request: NextRequest) {
  const body = await request.json();

  // VULNERABILITY: Direct object spread allows mass assignment
  const newUser = {
    id: users.length + 1,
    ...body, // All properties from request are accepted
  };

  users.push(newUser);

  const response = NextResponse.json(newUser, { status: 201 });
  response.headers.set('X-Powered-By', 'Next.js');
  return response;
}

// VULNERABILITY: User data modification without authorization
export async function PUT(request: NextRequest) {
  const body = await request.json();
  const { id, ...updates } = body;

  const userIndex = users.findIndex((u) => u.id === id);
  if (userIndex === -1) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // VULNERABILITY: Arbitrary field updates
  users[userIndex] = { ...users[userIndex], ...updates };

  return NextResponse.json(users[userIndex]);
}

// VULNERABILITY: User deletion without authorization
export async function DELETE(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const id = parseInt(searchParams.get('id') || '0');

  const userIndex = users.findIndex((u) => u.id === id);
  if (userIndex === -1) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  const deleted = users.splice(userIndex, 1)[0];
  return NextResponse.json({ deleted });
}
