// Admin page - Server Component with sensitive data
// VULNERABILITY: Exposes admin functionality via RSC

import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

// VULNERABILITY: Sensitive admin actions exposed as Server Actions
async function deleteUser(formData: FormData) {
  'use server';
  const userId = formData.get('userId') as string;
  console.log(`Deleting user: ${userId}`);
  return { deleted: true, userId };
}

async function modifyPermissions(formData: FormData) {
  'use server';
  const userId = formData.get('userId') as string;
  const role = formData.get('role') as string;
  console.log(`Modifying permissions: ${userId} -> ${role}`);
  return { modified: true, userId, role };
}

async function executeAdminCommand(formData: FormData) {
  'use server';
  const cmd = formData.get('cmd') as string;
  // VULNERABILITY: Command injection vector
  console.log(`Admin command: ${cmd}`);
  return { executed: cmd };
}

async function databaseQuery(formData: FormData) {
  'use server';
  const query = formData.get('query') as string;
  // VULNERABILITY: SQL injection vector
  console.log(`Database query: ${query}`);
  return { query, result: 'simulated result' };
}

// VULNERABILITY: Weak authentication check
async function checkAuth() {
  const headersList = headers();
  const authHeader = (await headersList).get('authorization');

  // VULNERABILITY: Hardcoded credential check, bypassable
  if (!authHeader || !authHeader.includes('admin')) {
    // Could be bypassed with: Authorization: admin
    return false;
  }
  return true;
}

export default async function AdminPage() {
  const isAuthed = await checkAuth();

  // Note: In real exploit, RSC payload could bypass this check
  // because the server action endpoints might not have the same checks

  return (
    <div>
      <h1>Admin Panel</h1>
      {isAuthed ? (
        <p>Welcome, Admin!</p>
      ) : (
        <p style={{ color: 'orange' }}>
          Authentication required (Add Authorization: admin header)
        </p>
      )}

      <section>
        <h2>User Management</h2>
        {/* VULNERABILITY: Admin actions via Server Actions */}
        <form action={deleteUser}>
          <input type="text" name="userId" placeholder="User ID to delete" />
          <button type="submit">Delete User</button>
        </form>

        <form action={modifyPermissions}>
          <input type="text" name="userId" placeholder="User ID" />
          <select name="role">
            <option value="user">User</option>
            <option value="admin">Admin</option>
            <option value="superadmin">Super Admin</option>
          </select>
          <button type="submit">Modify Permissions</button>
        </form>
      </section>

      <section>
        <h2>System Commands</h2>
        {/* VULNERABILITY: Direct command execution */}
        <form action={executeAdminCommand}>
          <input
            type="text"
            name="cmd"
            placeholder="System command"
            defaultValue="ls -la"
          />
          <button type="submit">Execute</button>
        </form>
      </section>

      <section>
        <h2>Database Access</h2>
        {/* VULNERABILITY: Direct database queries */}
        <form action={databaseQuery}>
          <textarea
            name="query"
            placeholder="SQL Query"
            defaultValue="SELECT * FROM users"
          />
          <button type="submit">Execute Query</button>
        </form>
      </section>

      {/* VULNERABILITY: Exposing server-side info */}
      <section>
        <h2>Debug Info</h2>
        <pre>
          {JSON.stringify(
            {
              nodeEnv: process.env.NODE_ENV,
              nodeVersion: process.version,
              platform: process.platform,
              cwd: process.cwd(),
              memoryUsage: process.memoryUsage(),
            },
            null,
            2
          )}
        </pre>
      </section>
    </div>
  );
}
