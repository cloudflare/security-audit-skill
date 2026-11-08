# Backend-as-a-Service and Full-Stack Framework Hunting

#### When to use this file

Reach for this file when the product's authorization boundary lives partly or wholly in a backend-as-a-service data layer or a full-stack framework's server runtime: Supabase or Postgres with row-level security exposed through an auto-generated API, Firebase security rules, Next.js or similar frameworks with server actions, route handlers, middleware, and server components, ORMs fed directly from request data, and platform-hosted cron, webhook, and preview deployments. In these targets the browser holds the API key and talks to the data layer directly, so the policy is the security boundary. Use `WEB-PROTOCOL-AND-AUTH.md` for session, JWT, and OAuth mechanics, `CLIENT-SIDE.md` for DOM and browser classes, `CLOUD-AND-DEPLOYMENT.md` for deployed environment drift, and `DATA-ISOLATION-AND-LIFECYCLE.md` for tenant scoping beyond the policy layer.

Pick classes from Phase 1. Split a large target into data-layer policies and privileges, server entry points and middleware, server-to-client data exposure, caching, platform-triggered routes and webhooks, billing and entitlements, and storage.

## Core discipline (include in every agent prompt for this domain)

```
- Treat every client-reachable data-layer table, function, storage bucket, realtime channel, and framework server endpoint as a public endpoint. The client key is not a secret; the policy and the in-handler check are the only controls.
- Authorization must be enforced at the last trusted decision point. A check in a page, layout, middleware, or UI component does not protect a server action, route handler, RPC function, or direct data-layer call that reaches the same effect.
- For each policy, write the effective predicate for each operation (select, insert, update, delete) and each role. Compare the read predicate with the write predicate, and the `using` clause with the `with check` clause.
- Source migrations are intent. Dashboard-created policies, environment overrides, and hosted auth settings may differ. If the decisive fact lives only in the hosted project or platform settings, use `needs_validation`.
- A secret or key counts only if it grants authority beyond what the client key already grants. Server-only variables exposed by a client prefix, and service-role keys in client-reachable code, are findings; the anon or publishable key is not.
- Do not call a deployed project, data layer, or platform API. Evaluate policies and handlers from source and in a local, sandboxed fixture with dummy principals.
```

## Data-layer policy attack classes (subagent_type: `general`)

**Table exposed without effective row-level security**
A table in a schema that the auto-generated API exposes has row-level security disabled, enabled with no policy for an operation the API allows, or granted broad privileges to the anonymous or authenticated role. Enumerate tables, views, and functions in exposed schemas and compare them with the policy set. Default grants and later migrations can reopen a closed table.

**Policy predicate too broad or incomplete**
A policy uses an always-true predicate, tests only that the caller is signed in, relies on a user-editable claim such as user metadata where an admin-only claim is required, matches on a client-supplied column, or covers `select` but omits the write check. A missing `with check` on insert or update lets a caller set the owner, tenant, role, or status column to another value. Check what a caller can change after the row exists.

**Privileged column and self-escalation**
A caller can update their own profile or membership row and set a role, plan, credit balance, verification flag, or tenant identifier. Row ownership is not column authority; check column-level grants, triggers that restrict changes, and views that omit sensitive columns.

**Definer functions, views, and RPC bypass**
A function that runs with its owner's privileges, or a view owned by a privileged role, is callable through the API and bypasses the table policies it reads or writes, takes a user identifier as a parameter instead of deriving it from the session, or has a mutable search path. Compare each exposed function's internal authorization with the table policies it sidesteps.

**Storage and realtime authorization**
Storage buckets are public, lack object policies, or authorize on a path segment the caller controls; signed upload or download URLs are not bound to principal and object; realtime channels or broadcast topics accept subscription or publish without the same row policy as the table. Review list and overwrite operations as well as reads.

**Weak client-side rules in document stores**
Security rules grant access to any signed-in user, mix up the existing resource with the incoming request resource, omit subcollections or wildcard paths, or trust a client-set claim or field. Compare read, create, update, and delete rules for each path.

## Framework server entry-point attack classes (subagent_type: `general`)

**Server action and route handler without in-handler authorization**
Server actions and route handlers are public network endpoints regardless of where they are imported. Each must authenticate and authorize the caller and check ownership of every identifier it receives. Compare each mutation with the authorization performed by sibling handlers and by the page that normally calls it.

**Middleware-only protection and matcher gaps**
Authentication relies on middleware that excludes some paths through its matcher, handles only some route shapes, trusts an internal header the client can send, or can be bypassed through framework data routes, rewrites, trailing-slash or encoding variants, or a vulnerable pinned framework version. Check the lockfile version against published advisories for middleware and routing, and verify that handlers re-check authorization independently.

**Server-to-client data exposure**
A whole database row or session object is passed to a client component, serialized into page props, returned from an action, or placed in a public environment variable, including password hashes, internal flags, tokens, other users' fields, or provider secrets. Trace what reaches the browser, not what the UI displays.

**Client-prefixed secret exposure**
A variable that the framework inlines into the client bundle because of its public prefix holds a server credential, or a server-only module is importable from client code. A publishable key is expected; a service-role, signing, or webhook secret is not.

**Cross-user cache leakage**
A cached function, fetch, or response keyed without the user or tenant identity returns one caller's data to another, or a statically generated or revalidated page embeds per-user content. Compare cache keys with every input the cached computation reads, including cookies and headers.

**Request-derived redirects, hosts, and fetches**
A redirect target, callback URL, or origin is taken from the request without validation, an image or fetch proxy allows a wildcard remote host, or a forwarded header selects a tenant or generates a reset link. Trace the value to the response or outbound request.

## Data-access and input attack classes (subagent_type: `general`)

**Mass assignment and filter injection**
Request bodies are spread into create or update calls, or an untrusted object is passed as a query filter, so a caller sets protected fields or injects operators that widen the match. Compare accepted input shape with the schema, check whether validation strips unknown keys, and compare the id used in the filter with the session identity.

**Raw query and dynamic expression sinks**
Unsafe raw-query helpers, dynamic ordering or column names, and expression builders accept request data. Trace field names and sort keys as well as values.

**Validation at the wrong layer**
Input schemas exist on the form or on one procedure but not on the alternate action, batch, import, or API route that performs the same write. Compare equivalent write paths.

## Platform-triggered route, webhook, and entitlement attack classes (subagent_type: `general`)

**Unauthenticated scheduled and internal routes**
Cron, queue, maintenance, or internal-callback routes are reachable by any caller because they do not verify the platform-provided secret or signature the platform sends. Establish whether the route performs a privileged action, sends messages, spends quota, or mutates data.

**Webhook signature and replay**
Payment, auth, or storage webhooks parse the body before verifying a signature, verify against a re-serialized body, skip verification in a fallback branch, accept events without idempotency, or trust event fields as identity.

**Client-trusted entitlements and billing**
Price, quantity, plan, coupon, or entitlement is read from the request or from the success redirect rather than from server state or a verified payment event, or entitlement is granted before the payment is confirmed. Check refund, downgrade, and replay paths.

**Preview, draft, and environment confusion**
Preview deployments or draft modes use production credentials or data, expose an unauthenticated preview path, or enable debug behavior from a header or query parameter. Establish which environment consumes each variable; platform-scoped values are often not visible in source.

## Universal moves (apply across the above)

- Build a matrix of every table, view, function, storage bucket, realtime topic, server action, and route handler against role and operation. Every cell must resolve to a visible predicate or check, or be recorded as unprotected.
- For every write, find the equivalent read and every sibling path that reaches the same effect, including bulk, import, retry, and admin variants.
- Follow each identifier from the request to the data access call and confirm the owner or tenant is bound there, not just earlier.
- Compare checked-in migrations with any generated types, seed data, and configuration files to spot drift. List what is decided only by hosted settings.
- Search for the client key, project URL, and role names in client code, then enumerate exactly what that key can reach.

## Validation rules (apply before reporting ANY finding here)

1. Write the effective policy or handler check for the operation, and the lower-trust principal that the client key and a normal sign-up give an attacker. Missing hardening alone is not a finding.
2. For data-layer policies, evaluate the predicate with dummy principals in a local fixture when a database or emulator is already available. Do not install one. If none is available, state the source-level evaluation and use `needs_validation` when a hosted setting or dashboard policy could change the result.
3. For server entry points, show the missing or insufficient check on the exact handler and a local call with dummy sessions where the existing test setup allows it. A check in a layout or middleware does not satisfy the handler requirement.
4. Do not classify a public or publishable key, a documented sample credential, or a value that the client is meant to hold as a leaked secret.
5. Do not send requests to any deployed project, hosting platform, or webhook provider, and do not use any real key found in source.
6. Return `confirmed` only with a complete source trace and a bounded local result. Return `needs_validation` with the exact hosted setting, dashboard policy, environment variable scope, or platform attachment required.
