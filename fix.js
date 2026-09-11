import fs from 'fs';

const serverFile = 'server.ts';
let code = fs.readFileSync(serverFile, 'utf8');

// The block to remove is from the rogue "    }" up to the first "  });"
// Let's just find "  // Global Error Handler" and reconstruct what's before it.

const parts = code.split('  // Global Error Handler');

let before = parts[0];
let after = parts[1];

// we want to truncate `before` exactly after `app.delete("/v1/pns/delete", proxyHandler);\n`

const marker = 'app.delete("/v1/pns/delete", proxyHandler);\\n';
let idx = before.indexOf('app.delete("/v1/pns/delete", proxyHandler);');
if (idx !== -1) {
  let cleanedBefore = before.substring(0, idx + 44);
  cleanedBefore += \`
  // --------------------------------------------------------------------------
  // Status Lists API (Public - Sanitized & Traversal-Protected)
  // --------------------------------------------------------------------------
  app.get('/status-lists/:segment/:poolId/aggregation', proxyHandler);
  app.get('/status-lists/:segment/:poolId/:listId', proxyHandler);

\`;
  code = cleanedBefore + '  // Global Error Handler' + after;
  fs.writeFileSync(serverFile, code);
  console.log("Fixed status-list parse error.");
} else {
  console.log("Could not find PNS delete handler.");
}
