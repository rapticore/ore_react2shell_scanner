// Forms page - Multiple Server Action patterns
// VULNERABILITY: Comprehensive server action attack surface

// Inline Server Actions
async function createUser(formData: FormData) {
  'use server';
  const data = Object.fromEntries(formData.entries());
  console.log('Creating user:', data);
  return { created: true, ...data };
}

async function updateProfile(formData: FormData) {
  'use server';
  const data = Object.fromEntries(formData.entries());
  // VULNERABILITY: Prototype pollution via object spread
  console.log('Updating profile:', data);
  return { updated: true, ...data };
}

async function sendEmail(formData: FormData) {
  'use server';
  const to = formData.get('to') as string;
  const subject = formData.get('subject') as string;
  const body = formData.get('body') as string;
  // VULNERABILITY: Email header injection
  console.log(`Sending email to ${to}: ${subject}`);
  return { sent: true, to, subject };
}

async function processPayment(formData: FormData) {
  'use server';
  const amount = formData.get('amount') as string;
  const card = formData.get('card') as string;
  // VULNERABILITY: Logging sensitive payment data
  console.log(`Processing payment: $${amount} on card ${card}`);
  return { processed: true, amount };
}

async function generateReport(formData: FormData) {
  'use server';
  const template = formData.get('template') as string;
  const data = formData.get('data') as string;
  // VULNERABILITY: Template injection
  console.log(`Generating report with template: ${template}`);
  return { generated: true, template };
}

async function importData(formData: FormData) {
  'use server';
  const source = formData.get('source') as string;
  const format = formData.get('format') as string;
  // VULNERABILITY: SSRF via source URL
  console.log(`Importing from ${source} in ${format} format`);
  return { imported: true, source, format };
}

async function webhookHandler(formData: FormData) {
  'use server';
  const url = formData.get('url') as string;
  const payload = formData.get('payload') as string;
  // VULNERABILITY: SSRF and payload injection
  console.log(`Webhook to ${url} with payload: ${payload}`);
  return { sent: true, url };
}

async function searchDatabase(formData: FormData) {
  'use server';
  const query = formData.get('query') as string;
  const table = formData.get('table') as string;
  // VULNERABILITY: SQL injection
  const sql = `SELECT * FROM ${table} WHERE name LIKE '%${query}%'`;
  console.log(`Executing: ${sql}`);
  return { results: [], query: sql };
}

export default function FormsPage() {
  return (
    <div>
      <h1>Server Action Forms</h1>
      <p>Each form below uses a different Server Action pattern.</p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        {/* User creation form */}
        <form action={createUser}>
          <h3>Create User</h3>
          <input type="text" name="username" placeholder="Username" />
          <input type="email" name="email" placeholder="Email" />
          <input type="password" name="password" placeholder="Password" />
          <input type="text" name="role" placeholder="Role" defaultValue="user" />
          <button type="submit">Create</button>
        </form>

        {/* Profile update form */}
        <form action={updateProfile}>
          <h3>Update Profile</h3>
          <input type="text" name="displayName" placeholder="Display Name" />
          <input type="text" name="bio" placeholder="Bio" />
          <input type="text" name="__proto__" placeholder="Proto (pollution test)" />
          <input type="text" name="constructor" placeholder="Constructor (pollution test)" />
          <button type="submit">Update</button>
        </form>

        {/* Email form */}
        <form action={sendEmail}>
          <h3>Send Email</h3>
          <input type="email" name="to" placeholder="To" />
          <input type="text" name="subject" placeholder="Subject" />
          <textarea name="body" placeholder="Message body"></textarea>
          <button type="submit">Send</button>
        </form>

        {/* Payment form */}
        <form action={processPayment}>
          <h3>Process Payment</h3>
          <input type="number" name="amount" placeholder="Amount" step="0.01" />
          <input type="text" name="card" placeholder="Card number" />
          <input type="text" name="cvv" placeholder="CVV" />
          <button type="submit">Pay</button>
        </form>

        {/* Report generation form */}
        <form action={generateReport}>
          <h3>Generate Report</h3>
          <input type="text" name="template" placeholder="Template name" />
          <textarea name="data" placeholder="Report data (JSON)"></textarea>
          <button type="submit">Generate</button>
        </form>

        {/* Data import form */}
        <form action={importData}>
          <h3>Import Data</h3>
          <input type="url" name="source" placeholder="Source URL" />
          <select name="format">
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="xml">XML</option>
          </select>
          <button type="submit">Import</button>
        </form>

        {/* Webhook form */}
        <form action={webhookHandler}>
          <h3>Send Webhook</h3>
          <input type="url" name="url" placeholder="Webhook URL" />
          <textarea name="payload" placeholder="Payload (JSON)"></textarea>
          <button type="submit">Send</button>
        </form>

        {/* Database search form */}
        <form action={searchDatabase}>
          <h3>Search Database</h3>
          <input type="text" name="table" placeholder="Table name" />
          <input type="text" name="query" placeholder="Search query" />
          <button type="submit">Search</button>
        </form>
      </div>
    </div>
  );
}
