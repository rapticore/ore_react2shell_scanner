// Server Component demonstrating dangerous HTML rendering patterns
// VULNERABILITY: Multiple XSS and injection vectors

// Simulated CMS content that could contain malicious payloads
const cmsContent = {
  title: 'Welcome to Our Site',
  body: `
    <div class="content">
      <p>This is content from our CMS.</p>
      <script>console.log('This should not execute but demonstrates the vulnerability')</script>
      <img src="x" onerror="alert('XSS')">
      <a href="javascript:alert('XSS')">Click me</a>
    </div>
  `,
  customStyles: `
    .content { color: red; }
    </style><script>alert('Style injection')</script><style>
  `,
};

// VULNERABILITY: Renders arbitrary HTML without sanitization
function UnsafeHtmlBlock({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// VULNERABILITY: Injects arbitrary styles
function UnsafeStyleBlock({ css }: { css: string }) {
  return <style dangerouslySetInnerHTML={{ __html: css }} />;
}

export async function DangerousHtmlRenderer() {
  // Simulate async content fetch
  await new Promise((resolve) => setTimeout(resolve, 50));

  return (
    <div className="cms-content">
      <h3>{cmsContent.title}</h3>

      {/* VULNERABILITY: Rendering unsanitized HTML */}
      <UnsafeHtmlBlock html={cmsContent.body} />

      {/* VULNERABILITY: Injecting unsanitized styles */}
      <UnsafeStyleBlock css={cmsContent.customStyles} />

      {/* VULNERABILITY: Template literal injection */}
      <div
        dangerouslySetInnerHTML={{
          __html: `<div data-rendered="${new Date().toISOString()}">${cmsContent.body}</div>`,
        }}
      />
    </div>
  );
}
