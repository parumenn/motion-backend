#!/usr/bin/env node
// Motion backend API smoke test (pages CRUD + API key auth).
//
// Usage:
//   MOTION_API_KEY=motion_... MOTION_BASE_URL=https://motion.parumenn.com \
//     node scripts/smoke-test.mjs
//
// The script creates one disposable page, exercises read / update /
// optimistic-lock conflict / reorder validation against it, and reports
// every check as PASS / FAIL / SKIP. It exits non-zero if any check fails.
//
// Notes on scope:
// - DELETE / restore / permanent-delete require a JWT (full-access) login:
//   API keys are refused with 403 by requireWriteAccess. With an API key the
//   script therefore checks that DELETE is refused (403) and leaves the
//   disposable page behind, printing its id for manual cleanup. With a
//   full-access key (MOTION_API_KEY set to a JWT, or a future full-scope
//   key), DELETE succeeds and the page is removed by the script itself.
// - No secrets are stored in this file; the key comes from the environment.
import { randomUUID } from "node:crypto";

const BASE = (process.env.MOTION_BASE_URL || "https://motion.parumenn.com").replace(/\/$/, "");
const KEY = process.env.MOTION_API_KEY;
if (!KEY) {
  console.error("MOTION_API_KEY is required (e.g. MOTION_API_KEY=motion_... node scripts/smoke-test.mjs)");
  process.exit(2);
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
}
function skip(name, detail = "") {
  console.log(`SKIP ${name}${detail ? ` — ${detail}` : ""}`);
}

async function req(method, path, { key = KEY, body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (key) headers.Authorization = `Bearer ${key}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    // non-JSON body: keep status only
  }
  return { status: res.status, json };
}

const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const title = `smoke-test-${stamp}`;
let pageId = null;
let created = null;

try {
  // 1. Auth: list without a key must be refused.
  {
    const r = await req("GET", "/api/pages", { key: null });
    check("list without key -> 401", r.status === 401, `got ${r.status}`);
  }
  // 2. Auth: a bogus motion_ key must be refused.
  {
    const r = await req("GET", "/api/pages", { key: "motion_smoke_test_bogus" });
    check("list with bogus key -> 403", r.status === 403, `got ${r.status}`);
  }
  // 3. List with the real key.
  {
    const r = await req("GET", "/api/pages");
    check("list with key -> 200 array", r.status === 200 && Array.isArray(r.json), `got ${r.status}`);
  }
  // 4. Unknown page -> 404.
  {
    const r = await req("GET", `/api/pages/nonexistent-${stamp}`);
    check("get unknown page -> 404", r.status === 404, `got ${r.status}`);
  }
  // 5. Create a disposable page.
  {
    const r = await req("POST", "/api/pages", {
      body: {
        id: `_${randomUUID().replace(/-/g, "").slice(0, 11)}`,
        title,
        parentId: null,
        blocks: [{ id: "b1", type: "p", content: "smoke test", checked: false, toggleOpen: false, children: [] }],
        isLocked: false,
        passwordHash: null,
      },
    });
    check("create page -> 201", r.status === 201 && r.json && r.json.id, `got ${r.status}`);
    pageId = r.json && r.json.id;
    created = r.json;
  }

  if (pageId) {
    // 6. Read it back.
    {
      const r = await req("GET", `/api/pages/${pageId}`);
      check("get created page -> title matches", r.status === 200 && r.json && r.json.title === title, `got ${r.status}`);
    }
    // 7. Update with the correct expectedUpdatedAt (optimistic lock, #5).
    let freshUpdatedAt = created && created.updated_at;
    {
      const get = await req("GET", `/api/pages/${pageId}`);
      freshUpdatedAt = get.json && get.json.updated_at;
      const r = await req("PUT", `/api/pages/${pageId}`, {
        body: {
          title: `${title}-updated`,
          parentId: null,
          blocks: created.blocks || [],
          isLocked: false,
          passwordHash: null,
          expectedUpdatedAt: freshUpdatedAt,
        },
      });
      check("put with fresh expectedUpdatedAt -> 200", r.status === 200, `got ${r.status}`);
    }
    // 8. Stale expectedUpdatedAt must be rejected without overwriting.
    {
      const r = await req("PUT", `/api/pages/${pageId}`, {
        body: {
          title: `${title}-stale-overwrite`,
          parentId: null,
          blocks: created.blocks || [],
          isLocked: false,
          passwordHash: null,
          expectedUpdatedAt: freshUpdatedAt,
        },
      });
      check("put with stale expectedUpdatedAt -> 409", r.status === 409, `got ${r.status}`);
      const get = await req("GET", `/api/pages/${pageId}`);
      check(
        "stale put left content unchanged",
        get.status === 200 && get.json && get.json.title === `${title}-updated`,
        `title is now ${get.json && get.json.title}`,
      );
    }
    // 9. Reorder validation: bogus sibling list -> 400.
    {
      const r = await req("POST", "/api/pages/reorder", {
        body: { parentId: null, orderedIds: ["nonexistent-1", "nonexistent-2"] },
      });
      check("reorder with bogus ids -> 400", r.status === 400, `got ${r.status}`);
    }
    // 10. Cleanup: DELETE works only with full access; API keys get 403.
    {
      const r = await req("DELETE", `/api/pages/${pageId}`);
      if (r.status === 200) {
        check("delete disposable page -> 200", true);
        pageId = null;
      } else if (r.status === 403) {
        skip("delete disposable page (API keys are refused 403)", `page ${pageId} left for manual cleanup`);
      } else {
        check("delete disposable page -> 200 or 403", false, `got ${r.status}`);
      }
    }
  }
} catch (err) {
  console.error(`ERROR ${err.message}`);
  process.exitCode = 1;
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
if (pageId) console.log(`NOTE: disposable page left behind (API-key scope cannot delete): ${pageId}`);
if (failed.length > 0) {
  console.log(`FAILED: ${failed.map((r) => r.name).join(", ")}`);
  process.exitCode = 1;
}
