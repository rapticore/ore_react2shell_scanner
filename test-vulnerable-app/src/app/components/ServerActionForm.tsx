// Server Actions - the primary attack vector for CVE-2025-55182
// VULNERABILITY: Multiple server action patterns that can be exploited

import { redirect } from 'next/navigation';

// VULNERABILITY: Server Action without proper input validation
async function submitContactForm(formData: FormData) {
  'use server';

  // VULNERABILITY: No input sanitization
  const name = formData.get('name') as string;
  const email = formData.get('email') as string;
  const message = formData.get('message') as string;

  // VULNERABILITY: Logging unsanitized input (potential log injection)
  console.log(`Contact form submission: ${name} - ${email} - ${message}`);

  // VULNERABILITY: Constructing commands/queries with user input
  // This simulates the type of vulnerability that CVE-2025-55182 exploits
  const query = `INSERT INTO contacts (name, email, message) VALUES ('${name}', '${email}', '${message}')`;
  console.log('Would execute query:', query);

  // VULNERABILITY: Returning user input in response
  return { success: true, name, email, message };
}

// VULNERABILITY: Server Action with command execution pattern
async function executeServerCommand(formData: FormData) {
  'use server';

  const command = formData.get('command') as string;

  // VULNERABILITY: This pattern is exactly what CVE-2025-55182 exploits
  // Malicious payload in the Flight protocol can trigger arbitrary code execution
  console.log(`Command requested: ${command}`);

  // In a real exploit, this would be:
  // const { exec } = require('child_process');
  // exec(command);

  return { executed: command, timestamp: new Date().toISOString() };
}

// VULNERABILITY: Server Action for file operations
async function handleFileUpload(formData: FormData) {
  'use server';

  const file = formData.get('file') as File;
  const filename = formData.get('filename') as string;

  // VULNERABILITY: Path traversal via filename
  // VULNERABILITY: No file type validation
  console.log(`File upload: ${filename}, size: ${file?.size}`);

  return { uploaded: true, filename };
}

// VULNERABILITY: Server Action with redirect (open redirect)
async function handleLogin(formData: FormData) {
  'use server';

  const username = formData.get('username') as string;
  const password = formData.get('password') as string;
  const returnUrl = formData.get('returnUrl') as string;

  // Simulated authentication
  if (username === 'admin' && password === 'admin') {
    // VULNERABILITY: Open redirect
    redirect(returnUrl || '/dashboard');
  }

  return { error: 'Invalid credentials' };
}

// VULNERABILITY: Server Action that modifies system state
async function updateSettings(formData: FormData) {
  'use server';

  const settings = Object.fromEntries(formData.entries());

  // VULNERABILITY: Arbitrary setting modification
  console.log('Settings update:', settings);

  // VULNERABILITY: Could modify environment variables, configs, etc.
  for (const [key, value] of Object.entries(settings)) {
    // Simulated dangerous operation
    console.log(`Setting ${key} = ${value}`);
  }

  return { updated: true, settings };
}

export function ServerActionForm() {
  return (
    <div className="server-actions">
      {/* VULNERABILITY: Contact form with no CSRF protection visible */}
      <form action={submitContactForm}>
        <h4>Contact Form (Server Action)</h4>
        <input type="text" name="name" placeholder="Name" />
        <input type="email" name="email" placeholder="Email" />
        <textarea name="message" placeholder="Message"></textarea>
        <button type="submit">Submit (Server Action)</button>
      </form>

      {/* VULNERABILITY: Command execution form */}
      <form action={executeServerCommand}>
        <h4>Server Command (Dangerous!)</h4>
        <input type="text" name="command" placeholder="Command" />
        <button type="submit">Execute</button>
      </form>

      {/* VULNERABILITY: File upload form */}
      <form action={handleFileUpload}>
        <h4>File Upload</h4>
        <input type="file" name="file" />
        <input type="text" name="filename" placeholder="Save as..." />
        <button type="submit">Upload</button>
      </form>

      {/* VULNERABILITY: Login form with returnUrl */}
      <form action={handleLogin}>
        <h4>Login (Open Redirect Vulnerable)</h4>
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <input type="hidden" name="returnUrl" value="https://evil.com" />
        <button type="submit">Login</button>
      </form>

      {/* VULNERABILITY: Settings update */}
      <form action={updateSettings}>
        <h4>Update Settings</h4>
        <input type="text" name="setting1" placeholder="Setting 1" />
        <input type="text" name="setting2" placeholder="Setting 2" />
        <input type="text" name="__proto__.polluted" placeholder="Prototype pollution" />
        <button type="submit">Update</button>
      </form>
    </div>
  );
}
