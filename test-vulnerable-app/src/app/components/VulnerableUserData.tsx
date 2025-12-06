// Server Component that fetches user data
// VULNERABILITY: This component is vulnerable to CVE-2025-55182
// The Flight protocol can be exploited to inject malicious payloads

interface UserDataProps {
  userId: string;
}

// Simulated database of users
const users: Record<string, { name: string; email: string; role: string }> = {
  '1': { name: 'Admin User', email: 'admin@example.com', role: 'admin' },
  '2': { name: 'Regular User', email: 'user@example.com', role: 'user' },
  '3': { name: 'Guest User', email: 'guest@example.com', role: 'guest' },
};

// VULNERABILITY: No input sanitization on userId
async function fetchUserData(userId: string) {
  // Simulate async database call
  await new Promise((resolve) => setTimeout(resolve, 100));

  // VULNERABILITY: Direct object access without validation
  return users[userId] || null;
}

export async function VulnerableUserData({ userId }: UserDataProps) {
  // VULNERABILITY: userId could contain malicious payload
  // that gets processed by Flight protocol
  const user = await fetchUserData(userId);

  if (!user) {
    return <div>User not found: {userId}</div>;
  }

  // VULNERABILITY: Rendering user data without proper escaping
  // The Flight protocol serializes this and could be exploited
  return (
    <div className="user-card">
      <h3>{user.name}</h3>
      <p>Email: {user.email}</p>
      <p>Role: {user.role}</p>
      {/* VULNERABILITY: Exposing internal state via RSC */}
      <input type="hidden" name="userId" value={userId} />
      <input type="hidden" name="userRole" value={user.role} />
    </div>
  );
}
