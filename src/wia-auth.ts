// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Windows Integrated Auth (WIA) for on-prem Azure DevOps Server / TFS.
//
// This is the Node equivalent of PowerShell's `Invoke-RestMethod -UseDefaultCredentials`:
// it authenticates as the logged-in user over SPNEGO/Negotiate (Kerberos), so a
// domain-joined host on the corporate network needs no PAT. The token is minted
// from the OS credential cache via the optional native `kerberos` module.
//
// SPNEGO is a multi-leg handshake: the client sends a token, the server may reply
// 401 with a continuation token, and the client steps again until the server returns
// a non-401. Gallagher's TFS completes in 3 legs (MIC exchange). All legs must ride
// the SAME TCP connection, so the request handler below pins a keep-alive agent.
//
// SPIKE / PROTOTYPE scope and limitations:
//   - SPNEGO/Kerberos only. NTLM (which also needs a different message format) is not
//     implemented; if the server offers *only* NTLM this fails.
//   - The WebApi connection (typed-rest-client) is fully handled here. Direct-`fetch`
//     tools are NOT multi-leg capable yet (undici gives no socket affinity) — see
//     index.ts and FORK-ONPREM-WIA.md.
//   - Requires the optional `kerberos` native module (`npm install kerberos`) and a
//     usable ticket: a domain-joined Windows host, or a *nix host with a kinit'd TGT.
//   - Off the corporate network / VPN the on-prem host won't resolve at all.

import * as http from "node:http";
import * as https from "node:https";
import type { IRequestHandler, IHttpClient, IHttpClientResponse, IRequestInfo } from "typed-rest-client/Interfaces.js";
import { logger } from "./logger.js";

// Maximum SPNEGO legs before giving up (a backstop against a server that keeps
// replying 401 with continuation tokens). Real handshakes settle in 2-3 legs.
const MAX_NEGOTIATE_LEGS = 10;

// Minimal shape of the bits of the `kerberos` module we use. We avoid a compile-time
// dependency (and @types) by declaring it locally and loading it dynamically.
interface KerberosClient {
  // Advances the SPNEGO handshake. step("") yields the initial token; on later legs
  // `challenge` is the server's base64 continuation token from its 401 response.
  step(challenge: string): Promise<string>;
}

interface KerberosModule {
  initializeClient(service: string, options?: Record<string, unknown>): Promise<KerberosClient>;
  GSS_MECH_OID_SPNEGO?: unknown;
}

let kerberosModulePromise: Promise<KerberosModule> | undefined;

async function loadKerberos(): Promise<KerberosModule> {
  if (!kerberosModulePromise) {
    // Non-literal specifier: keeps TypeScript from statically resolving the optional
    // native module (it isn't installed by default and ships no type declarations).
    // eslint-disable-next-line @typescript-eslint/no-inferrable-types -- the `string` annotation is the point: it widens away the literal type
    const kerberosSpecifier: string = "kerberos";
    kerberosModulePromise = import(kerberosSpecifier)
      .then((mod) => ((mod as { default?: KerberosModule }).default ?? mod) as KerberosModule)
      .catch((error: unknown) => {
        kerberosModulePromise = undefined; // allow a later retry once the module is installed
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
          "Windows Integrated Auth ('--authentication wia') requires the optional native 'kerberos' module. " +
            "Install it with `npm install kerberos` on a domain-joined Windows host (or a *nix host with a Kerberos ticket). " +
            `Original load error: ${detail}`
        );
      });
  }
  return kerberosModulePromise;
}

/**
 * Derive the Kerberos service principal for the Azure DevOps host from the org URL.
 * The `kerberos` module expects `service@host`; on Windows SSPI this maps to the
 * SPN `HTTP/<host>`, which is what IIS registers for an integrated-auth site.
 */
export function deriveServicePrincipal(orgUrl: string): string {
  let host: string;
  try {
    host = new URL(orgUrl).hostname;
  } catch {
    throw new Error(`Cannot derive a Kerberos service principal: '${orgUrl}' is not a valid URL.`);
  }
  if (!host) {
    throw new Error(`Cannot derive a Kerberos service principal: '${orgUrl}' has no host.`);
  }
  return `HTTP@${host}`;
}

/** Pull the base64 continuation token out of a `WWW-Authenticate: Negotiate <token>` header. */
function extractServerNegotiateToken(header: string | string[] | undefined): string {
  const value = Array.isArray(header) ? header.join(", ") : (header ?? "");
  const match = value.match(/Negotiate\s+([^\s,]+)/i);
  return match ? match[1] : "";
}

/** True if a 401 response offers the Negotiate scheme. */
function offersNegotiate(response: IHttpClientResponse): boolean {
  const message = response?.message;
  if (!message || message.statusCode !== 401) {
    return false;
  }
  const header = message.headers["www-authenticate"];
  const value = Array.isArray(header) ? header.join(", ") : (header ?? "");
  return /negotiate/i.test(value);
}

/**
 * Mints SPNEGO/Negotiate tokens for a single Azure DevOps host using the caller's
 * own Kerberos credentials. One instance per server URL.
 */
export class WiaAuthenticator {
  private readonly servicePrincipal: string;

  constructor(orgUrl: string) {
    this.servicePrincipal = deriveServicePrincipal(orgUrl);
    logger.debug(`WiaAuthenticator: service principal resolved to '${this.servicePrincipal}'`);
  }

  /** Initialize a fresh SPNEGO client for one handshake (one per request). */
  async createClient(): Promise<KerberosClient> {
    const kerberos = await loadKerberos();
    const options: Record<string, unknown> = {};
    if (kerberos.GSS_MECH_OID_SPNEGO) {
      options.mechOID = kerberos.GSS_MECH_OID_SPNEGO;
    }
    return kerberos.initializeClient(this.servicePrincipal, options);
  }

  /**
   * Produce the first-leg base64 Negotiate token. Used by the direct-`fetch` path,
   * which can only attempt single-leg auth. The WebApi handler uses createClient()
   * directly so it can step through every leg.
   */
  async getNegotiateToken(): Promise<string> {
    const client = await this.createClient();
    const token = await client.step("");
    if (!token) {
      throw new Error(`Kerberos returned an empty Negotiate token for '${this.servicePrincipal}'. Is there a valid ticket for this host?`);
    }
    logger.debug("WiaAuthenticator: minted initial Negotiate token");
    return token;
  }
}

/**
 * A typed-rest-client request handler that completes a multi-leg SPNEGO handshake.
 * The WebApi connection uses typed-rest-client (not global fetch), so this handler —
 * not the fetch interceptor in index.ts — covers every typed API call.
 *
 * Flow: typed-rest-client sends the request unauthenticated, gets a 401 offering
 * Negotiate, and hands it to handleAuthentication. We then step the Kerberos client
 * and re-issue the request on a pinned keep-alive socket, feeding each leg's server
 * continuation token back in, until the server returns a non-401.
 */
export function createNegotiateRequestHandler(authenticator: WiaAuthenticator, maxLegs: number = MAX_NEGOTIATE_LEGS): IRequestHandler {
  // All legs of one handshake must share a TCP connection, so pin a single-socket
  // keep-alive agent for this connection's lifetime.
  let keepAliveAgent: http.Agent | https.Agent | undefined;

  function requestRaw(httpClient: IHttpClient, info: IRequestInfo, data: string): Promise<IHttpClientResponse> {
    return new Promise<IHttpClientResponse>((resolve, reject) => {
      httpClient.requestRawWithCallback(info, data, (err, res) => (err ? reject(err) : resolve(res)));
    });
  }

  return {
    // Nothing to set up preemptively: token minting is async and prepareRequest is
    // synchronous, so we authenticate reactively on the 401 challenge instead.
    prepareRequest(options): void {
      void options;
    },

    canHandleAuthentication(response: IHttpClientResponse): boolean {
      return offersNegotiate(response);
    },

    async handleAuthentication(httpClient: IHttpClient, requestInfo: IRequestInfo, objs: unknown): Promise<IHttpClientResponse> {
      const client = await authenticator.createClient();
      if (!keepAliveAgent) {
        const isSsl = (httpClient as { isSsl?: boolean }).isSsl ?? requestInfo.parsedUrl.protocol === "https:";
        keepAliveAgent = isSsl ? new https.Agent({ keepAlive: true, maxSockets: 1 }) : new http.Agent({ keepAlive: true, maxSockets: 1 });
      }

      let challenge = "";
      let response: IHttpClientResponse | undefined;
      for (let leg = 0; leg < maxLegs; leg++) {
        const token = await client.step(challenge);
        const legInfo: IRequestInfo = {
          httpModule: requestInfo.httpModule,
          parsedUrl: requestInfo.parsedUrl,
          options: {
            ...requestInfo.options,
            agent: keepAliveAgent,
            headers: {
              ...requestInfo.options.headers,
              Authorization: `Negotiate ${token}`,
              Connection: "keep-alive",
            },
          },
        };

        response = await requestRaw(httpClient, legInfo, objs as string);
        if (response.message.statusCode !== 401) {
          // Success (or a non-auth error). Leave the body unread for the caller —
          // typed-rest-client returns this response straight through and reads it once.
          logger.debug(`WiaAuthenticator: SPNEGO handshake settled on leg ${leg + 1} with status ${response.message.statusCode}`);
          return response;
        }

        const serverToken = extractServerNegotiateToken(response.message.headers["www-authenticate"]);
        // Drain the 401 body so the pinned socket is freed for the next leg.
        await response.readBody();
        if (!serverToken) {
          // Server won't continue the handshake (e.g. fell back to a scheme we don't do).
          return response;
        }
        challenge = serverToken;
      }

      logger.warn(`WiaAuthenticator: SPNEGO handshake did not settle within ${maxLegs} legs`);
      return response as IHttpClientResponse;
    },
  };
}
