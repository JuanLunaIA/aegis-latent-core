// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

/**
 * Fail the build if a server-only secret reached browser-served output.
 *
 * `dashboard/tests/no-fabrication.test.ts` greps the source for the mistake
 * that leaks the audit key (pairing it with `NEXT_PUBLIC_`). That catches the
 * known shape and nothing else. This runs after `next build` and inspects what
 * the browser is actually served, so an inlining path nobody predicted — a new
 * `next.config` option, a client component importing a server module, a
 * dependency echoing `process.env` — still fails closed.
 *
 * Scope: `.next/static` is served verbatim to browsers, and prerendered
 * `.html` / `.rsc` payloads under `.next/server/app` are sent to them too.
 * The rest of `.next/server` stays on the server and is not scanned.
 *
 * Usage:
 *   AEGIS_DASHBOARD_API_KEY=<value used for the build> \
 *     node scripts/check-client-bundle-secrets.mjs
 *
 * Exits 0 when clean, 1 on a finding, 2 when it cannot do its job (no build
 * output, no secret to look for) — never silently pass.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const NEXT_DIR = join(ROOT, ".next");

/** Directories whose contents reach a browser. */
const CLIENT_SERVED = [
  join(NEXT_DIR, "static"),
  join(NEXT_DIR, "server", "app"),
];

/** Within .next/server/app, only these are shipped to the client. */
const CLIENT_SERVED_SERVER_EXT = [".html", ".rsc", ".body"];

/**
 * Server-only variables. A build value appearing verbatim in client output
 * means it was inlined; that is the leak, whatever the mechanism.
 */
const SERVER_ONLY_VARS = ["AEGIS_DASHBOARD_API_KEY"];

/** A NEXT_PUBLIC_* name shaped like a credential is a leak by construction. */
const PUBLIC_CREDENTIAL_NAME = /NEXT_PUBLIC_[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*/g;

function fail(message) {
  console.error(`\n  client bundle secret check FAILED\n\n${message}\n`);
  process.exit(1);
}

function cannotCheck(message) {
  console.error(`\n  client bundle secret check COULD NOT RUN\n\n${message}\n`);
  process.exit(2);
}

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // absent directory is handled by the caller's existence check
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

function clientServedFiles() {
  const files = [];
  for (const dir of CLIENT_SERVED) {
    let isDir = false;
    try {
      isDir = statSync(dir).isDirectory();
    } catch {
      isDir = false;
    }
    if (!isDir) continue;

    const restrictExtension = dir.endsWith(join("server", "app"));
    for (const file of walk(dir)) {
      if (restrictExtension && !CLIENT_SERVED_SERVER_EXT.some((e) => file.endsWith(e))) {
        continue;
      }
      files.push(file);
    }
  }
  return files;
}

function main() {
  const secrets = SERVER_ONLY_VARS.map((name) => [name, process.env[name]]).filter(
    ([, value]) => typeof value === "string" && value.length > 0,
  );

  if (secrets.length === 0) {
    cannotCheck(
      `None of ${SERVER_ONLY_VARS.join(", ")} is set, so there is no value to search for.\n` +
        "Run this with the same environment used for `next build`, otherwise the check\n" +
        "would pass without having looked at anything.",
    );
  }

  // A short value would match unrelated bytes and report a false leak.
  for (const [name, value] of secrets) {
    if (value.length < 8) {
      cannotCheck(
        `${name} is ${value.length} characters. A value this short cannot be\n` +
          "distinguished from incidental bytes in a bundle. Use a longer build placeholder.",
      );
    }
  }

  const files = clientServedFiles();
  if (files.length === 0) {
    cannotCheck(
      `No browser-served files under ${relative(ROOT, NEXT_DIR)}.\n` +
        "Run `npm run build` first — an unbuilt tree would pass trivially.",
    );
  }

  const findings = [];
  for (const file of files) {
    const contents = readFileSync(file, "utf8");
    const shown = relative(ROOT, file);

    for (const [name, value] of secrets) {
      if (contents.includes(value)) {
        findings.push(`${shown}: contains the value of ${name}`);
      }
    }

    for (const match of new Set(contents.match(PUBLIC_CREDENTIAL_NAME) ?? [])) {
      findings.push(`${shown}: exposes a credential-shaped public variable ${match}`);
    }
  }

  if (findings.length > 0) {
    fail(
      `${findings.length} finding(s) in browser-served output:\n\n` +
        findings.map((f) => `  - ${f}`).join("\n") +
        "\n\nA server-only credential must never be inlined into client output.\n" +
        "Read it inside a server route handler (see src/lib/aegis-client.server.ts).",
    );
  }

  console.log(
    `client bundle secret check passed: ${files.length} browser-served file(s), ` +
      `${secrets.length} server-only value(s) searched, 0 findings`,
  );
}

main();
