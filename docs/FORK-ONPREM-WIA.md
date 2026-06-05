# Fork Notes: On-Prem Azure DevOps + Windows Integrated Auth (WIA) — SPIKE

This document describes a **prototype** auth mode that lets the MCP server talk to
on-prem Azure DevOps Server / TFS **without a PAT**, by authenticating as the
logged-in user over SPNEGO/Negotiate (Kerberos) — the Node equivalent of
PowerShell's `Invoke-RestMethod -UseDefaultCredentials`.

> **Status: experimental spike — validated against live on-prem TFS.** The WebApi
> path completes a full multi-leg SPNEGO handshake and `core_list_projects` returns
> real data with no PAT. Not hardened, not the default, and direct-`fetch` tools are
> not covered yet. See _Limitations_ before relying on it.

## Why

On a domain-joined host on the corporate network, the OS already holds a Kerberos
ticket for the logged-in user. WIA reuses that ticket to authenticate, so there is
**no token to create, store, or rotate** — unlike PAT auth (`ADO_PAT`). This mirrors
the approach a sibling team took with a PowerShell `tfs.ps1` script
(`-UseDefaultCredentials`), but keeps the MCP's typed-tool surface.

## What Changed In This Fork

### 1) New `--authentication wia` mode

- `src/index.ts`: `wia` added to the `--authentication` choices.
- `src/auth.ts`: `createAuthenticator("wia")` returns a **placeholder** token
  (`"wia-negotiate"`). WIA has no bearer token; the placeholder only exists so the
  direct-`fetch` tools still emit an `Authorization: Bearer …` header that the
  interceptor can rewrite.

### 2) New module `src/wia-auth.ts`

- `deriveServicePrincipal(orgUrl)` → `HTTP@<host>` (the Kerberos SPN; maps to the
  IIS-registered `HTTP/<host>` SPN on Windows SSPI).
- `WiaAuthenticator.createClient()` initializes a SPNEGO stepping client from the OS
  credential cache via the optional native `kerberos` module (loaded dynamically);
  `getNegotiateToken()` is a first-leg convenience for the `fetch` path.
- `createNegotiateRequestHandler(...)` returns a `typed-rest-client` `IRequestHandler`
  for the `WebApi` connection. On a `401 WWW-Authenticate: Negotiate`, it runs the
  **multi-leg** SPNEGO handshake: `step()` → send `Authorization: Negotiate <token>` →
  feed the server's continuation token back into `step()` → repeat until non-401. All
  legs ride one pinned keep-alive socket (`maxSockets: 1`); intermediate 401 bodies are
  drained to free the socket, the final response is left unread for the caller.

### 3) Two injection points (mirrors the PAT design)

The MCP makes HTTP calls two ways, so WIA hooks both:

- **`WebApi` connection** (typed-rest-client) → the Negotiate `IRequestHandler` above
  (`getAzureDevOpsClient` in `src/index.ts`).
- **Direct `fetch` tools** (`tools/auth.ts`, search, etc.) → a `globalThis.fetch`
  interceptor in `src/index.ts` rewrites `Authorization: Bearer <placeholder>` to a
  freshly minted `Authorization: Negotiate <token>`.

### 4) `kerberos` is an optional dependency

- Added to `optionalDependencies` in `package.json`. It is a **native, platform-bound**
  module; a failed build does not break installs for PAT/cloud users. It is loaded
  lazily and only when `--authentication wia` is used. If it is missing, the server
  throws a clear "install kerberos" error rather than failing at startup.

## Usage

```jsonc
{
  "command": ["node", "/path/to/azure-devops-mcp/dist/index.js", "https://ado.company.local/tfs/DefaultCollection", "--authentication", "wia", "-d", "core", "work", "work-items", "repositories"],
}
```

One-time on the host: `npm install kerberos` (requires the platform build toolchain).

## Limitations (read before relying on this)

- **`WebApi` tools only.** The typed `WebApi` connection (core, work, work-items, repos,
  wiki, pipelines, test-plans) is fully handled and validated. The **direct-`fetch`
  tools are not multi-leg capable** — `tools/auth.ts` (`core_get_identity_ids`) and the
  search tools set a single `Negotiate` header via the fetch interceptor, but undici
  gives no socket affinity to complete the handshake, so they will 401 under WIA. The
  search domain is already on-prem-unsupported in this fork regardless. Making the fetch
  tools work needs a dedicated multi-leg `https` helper (follow-up).
- **SPNEGO/Kerberos only.** Gallagher's TFS completes the handshake in 3 legs (a MIC
  exchange), which this handler does. **NTLM is not implemented** — it uses a different
  message format. If a server offers _only_ NTLM (no Kerberos SPN, IP-address URL,
  missing/incorrect SPN), this mode fails.
- **Requires a usable ticket.** A domain-joined Windows host on the corporate network
  / VPN, or a \*nix host with a `kinit`'d TGT. Off-network the host won't resolve at all.
- **Native dependency.** `kerberos` must build on (or ship a prebuilt binary for) the
  host. Windows uses SSPI; Linux/mac use system GSSAPI/MIT Kerberos libraries.
- **SPN assumption.** The SPN is derived as `HTTP@<host-from-org-url>`. A host behind a
  load balancer / alias with a different registered SPN would need an override (not yet
  exposed as a flag).

## Tests

- `test/src/wia-auth.test.ts` — SPN derivation, the `wia` placeholder authenticator,
  `getNegotiateToken` (with a virtual `kerberos` mock), and the Negotiate request
  handler's 401 detection + retry-header behavior.

## Validation (done — 2026-06-05)

Validated on a domain-joined Windows 11 host (`GALLAGHER.LOCAL`) on-network against
`https://ggltfs.local.gallagher.io/tfs/Gallagher`:

- Kerberos minted a 520-byte SPNEGO token for `HTTP@ggltfs.local.gallagher.io`.
- Raw probe confirmed the server runs **multi-leg SPNEGO** (401 + continuation token,
  `negState request-mic`), settling at HTTP 200 on **leg 3**.
- `WebApi.getCoreApi().getProjects()` through the handler returned all 14 projects.
- The real MCP server booted with `--authentication wia -d core` and `core_list_projects`
  returned the same 14 projects over stdio — no PAT anywhere.

To re-run: `npm install && npm install kerberos && npm run build`, then start the server
with the on-prem collection URL + `--authentication wia` on a domain-joined, on-network
host (`klist` should show a TGT). If everything 401s: confirm the `HTTP/<host>` SPN
exists (`setspn -L <service-account>`), that Kerberos (not just NTLM) is offered, and
that you're on-network.
