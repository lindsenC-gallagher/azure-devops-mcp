#!/usr/bin/env node

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getBearerHandler, getPersonalAccessTokenHandler, WebApi } from "azure-devops-node-api";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

import { createAuthenticator } from "./auth.js";
import { WiaAuthenticator, createNegotiateRequestHandler } from "./wia-auth.js";
import { resolveDeploymentContext } from "./deployment.js";
import { logger } from "./logger.js";
import { getOrgTenant } from "./org-tenants.js";
//import { configurePrompts } from "./prompts.js";
import { configureAllTools } from "./tools.js";
import { UserAgentComposer } from "./useragent.js";
import { packageVersion } from "./version.js";
import { DomainsManager } from "./shared/domains.js";

function isGitHubCodespaceEnv(): boolean {
  return process.env.CODESPACES === "true" && !!process.env.CODESPACE_NAME;
}

const defaultAuthenticationType = isGitHubCodespaceEnv() ? "azcli" : "interactive";

// Parse command line arguments using yargs
const argv = yargs(hideBin(process.argv))
  .scriptName("mcp-server-azuredevops")
  .usage("Usage: $0 <organization> [options]")
  .version(packageVersion)
  .command("$0 <organization> [options]", "Azure DevOps MCP Server", (yargs) => {
    yargs.positional("organization", {
      describe: "Azure DevOps organization name or full organization URL",
      type: "string",
      demandOption: true,
    });
  })
  .option("domains", {
    alias: "d",
    describe: "Domain(s) to enable: 'all' for everything, or specific domains like 'repositories builds work'. Defaults to 'all'.",
    type: "string",
    array: true,
    default: "all",
  })
  .option("authentication", {
    alias: "a",
    describe: "Type of authentication to use",
    type: "string",
    choices: ["interactive", "azcli", "env", "envvar", "pat", "wia"],
    default: defaultAuthenticationType,
  })
  .option("tenant", {
    alias: "t",
    describe: "Azure tenant ID (optional, applied when using 'interactive' and 'azcli' type of authentication)",
    type: "string",
  })
  .help()
  .parseSync();

const deployment = resolveDeploymentContext(argv.organization as string);
export const orgName = deployment.organizationName ?? deployment.organizationInput;
const orgUrl = deployment.organizationUrl;

const domainsManager = new DomainsManager(argv.domains);
export const enabledDomains = domainsManager.getEnabledDomains();

function getAzureDevOpsClient(getAzureDevOpsToken: () => Promise<string>, userAgentComposer: UserAgentComposer, authType: string, wiaAuthenticator?: WiaAuthenticator): () => Promise<WebApi> {
  return async () => {
    const requestSettings = {
      productName: "AzureDevOps.MCP",
      productVersion: packageVersion,
      userAgent: userAgentComposer.userAgent,
    };

    // Windows Integrated Auth uses a Negotiate request handler instead of a token,
    // because typed-rest-client (the WebApi HTTP stack) handles the 401 challenge.
    if (authType === "wia" && wiaAuthenticator) {
      const negotiateHandler = createNegotiateRequestHandler(wiaAuthenticator);
      return new WebApi(orgUrl, negotiateHandler, undefined, requestSettings);
    }

    const accessToken = await getAzureDevOpsToken();
    const authHandler = authType === "pat" ? getPersonalAccessTokenHandler(accessToken) : getBearerHandler(accessToken);
    const connection = new WebApi(orgUrl, authHandler, undefined, requestSettings);
    return connection;
  };
}

async function main() {
  logger.info("Starting Azure DevOps MCP Server", {
    organization: deployment.organizationInput,
    organizationName: deployment.organizationName,
    organizationUrl: orgUrl,
    isHosted: deployment.isHosted,
    authentication: argv.authentication,
    tenant: argv.tenant,
    domains: argv.domains,
    enabledDomains: Array.from(enabledDomains),
    version: packageVersion,
    isCodespace: isGitHubCodespaceEnv(),
  });

  const server = new McpServer({
    name: "Azure DevOps MCP Server",
    version: packageVersion,
    icons: [
      {
        src: "https://cdn.vsassets.io/content/icons/favicon.ico",
      },
    ],
  });

  const userAgentComposer = new UserAgentComposer(packageVersion);
  server.server.oninitialized = () => {
    userAgentComposer.appendMcpClientInfo(server.server.getClientVersion());
  };
  const shouldResolveTenant = deployment.isHosted && ["interactive", "azcli", "env"].includes(argv.authentication);
  const tenantId = shouldResolveTenant && deployment.organizationName ? ((await getOrgTenant(deployment.organizationName)) ?? argv.tenant) : argv.tenant;
  const authenticator = createAuthenticator(argv.authentication, tenantId);

  // Windows Integrated Auth: mint Negotiate tokens from the caller's Kerberos
  // credentials. Used by both the WebApi Negotiate handler and the fetch interceptor.
  const wiaAuthenticator = argv.authentication === "wia" ? new WiaAuthenticator(orgUrl) : undefined;

  if (argv.authentication === "wia" && wiaAuthenticator) {
    // Direct-REST tools (tools/auth.ts, search, etc.) set `Authorization: Bearer <placeholder>`
    // via the token provider. Rewrite that to a freshly minted `Negotiate` header, mirroring
    // the PAT interceptor below. The WebApi connection is handled separately by its own handler.
    // NOTE (spike limitation): this is single-leg only — undici gives no socket affinity to
    // complete the multi-leg SPNEGO handshake the on-prem server requires, so these few
    // direct-fetch tools will 401 under WIA. The typed WebApi tools (the bulk) work fully.
    // See docs/FORK-ONPREM-WIA.md.
    const _originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const requestHeaders = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      if (requestHeaders.get("Authorization")?.startsWith("Bearer ")) {
        const token = await wiaAuthenticator.getNegotiateToken();
        requestHeaders.set("Authorization", `Negotiate ${token}`);
        if (input instanceof Request) {
          input = new Request(input, { headers: requestHeaders });
          init = undefined;
        } else {
          init = { ...init, headers: requestHeaders };
        }
      }
      return _originalFetch(input, init);
    };
    logger.debug("WIA mode: global fetch interceptor installed to rewrite Bearer -> Negotiate auth headers");
  }

  if (argv.authentication === "pat") {
    const rawPat = await authenticator();
    const basicValue = Buffer.from(`:${rawPat}`, "utf8").toString("base64");
    const _originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const requestHeaders = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      if (requestHeaders.get("Authorization")?.startsWith("Bearer ")) {
        requestHeaders.set("Authorization", `Basic ${basicValue}`);
        if (input instanceof Request) {
          input = new Request(input, { headers: requestHeaders });
          init = undefined;
        } else {
          init = { ...init, headers: requestHeaders };
        }
      }
      return _originalFetch(input, init);
    };
    logger.debug("PAT mode: global fetch interceptor installed to rewrite Bearer -> Basic auth headers");
  }

  // removing prompts untill further notice
  // configurePrompts(server);

  configureAllTools(server, authenticator, getAzureDevOpsClient(authenticator, userAgentComposer, argv.authentication, wiaAuthenticator), () => userAgentComposer.userAgent, enabledDomains);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  logger.error("Fatal error in main():", error);
  process.exit(1);
});
