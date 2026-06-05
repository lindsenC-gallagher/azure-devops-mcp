// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, expect, it, jest, beforeEach } from "@jest/globals";

jest.mock("../../src/logger.js", () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mocked so importing createAuthenticator (via src/auth) doesn't pull in the real
// Azure identity stack, whose internal "./logger.js" import collides with the
// jest moduleNameMapper. Mirrors pat-auth.test.ts.
jest.mock("@azure/identity", () => ({
  AzureCliCredential: jest.fn(),
  ChainedTokenCredential: jest.fn(),
  DefaultAzureCredential: jest.fn(),
}));

jest.mock("@azure/msal-node", () => ({
  PublicClientApplication: jest.fn(),
}));

jest.mock("open", () => jest.fn());

// `kerberos` is an optional native module not installed in CI. A virtual mock lets us
// exercise token minting without a real Kerberos stack. Tests that need the
// "module missing" path override this per-test.
const mockStep = jest.fn<(challenge: string) => Promise<string>>();
const mockInitializeClient = jest.fn<(service: string, options?: Record<string, unknown>) => Promise<{ step: typeof mockStep }>>();
jest.mock("kerberos", () => ({ initializeClient: mockInitializeClient }), { virtual: true });

import { deriveServicePrincipal, WiaAuthenticator, createNegotiateRequestHandler } from "../../src/wia-auth";
import { createAuthenticator } from "../../src/auth";

describe("WIA (Windows Integrated Auth)", () => {
  beforeEach(() => {
    mockStep.mockReset();
    mockInitializeClient.mockReset();
    mockStep.mockResolvedValue("BASE64-SPNEGO-TOKEN");
    mockInitializeClient.mockResolvedValue({ step: mockStep });
  });

  describe("deriveServicePrincipal", () => {
    it("derives HTTP@<host> from an on-prem collection URL", () => {
      expect(deriveServicePrincipal("https://ggltfs.local.gallagher.io/tfs/Gallagher")).toBe("HTTP@ggltfs.local.gallagher.io");
    });

    it("derives HTTP@<host> from a hosted org URL", () => {
      expect(deriveServicePrincipal("https://dev.azure.com/contoso")).toBe("HTTP@dev.azure.com");
    });

    it("ignores port and path", () => {
      expect(deriveServicePrincipal("https://ado.company.local:8080/tfs/DefaultCollection")).toBe("HTTP@ado.company.local");
    });

    it("throws on a non-URL input", () => {
      expect(() => deriveServicePrincipal("not a url")).toThrow("not a valid URL");
    });
  });

  describe("createAuthenticator('wia')", () => {
    it("returns a placeholder token for the fetch interceptor to rewrite", async () => {
      const authenticator = createAuthenticator("wia");
      await expect(authenticator()).resolves.toBe("wia-negotiate");
    });
  });

  describe("WiaAuthenticator.getNegotiateToken", () => {
    it("initializes a Kerberos client for the host SPN and returns the token", async () => {
      const auth = new WiaAuthenticator("https://ado.company.local/tfs/DefaultCollection");
      const token = await auth.getNegotiateToken();

      expect(token).toBe("BASE64-SPNEGO-TOKEN");
      expect(mockInitializeClient).toHaveBeenCalledWith("HTTP@ado.company.local", expect.any(Object));
      expect(mockStep).toHaveBeenCalledWith("");
    });

    it("throws when Kerberos returns an empty token", async () => {
      mockStep.mockResolvedValue("");
      const auth = new WiaAuthenticator("https://ado.company.local/tfs/DefaultCollection");

      await expect(auth.getNegotiateToken()).rejects.toThrow("empty Negotiate token");
    });
  });

  describe("createNegotiateRequestHandler", () => {
    const handler = createNegotiateRequestHandler(new WiaAuthenticator("https://ado.company.local/tfs/DefaultCollection"));

    const makeResponse = (statusCode: number, headers: Record<string, string | string[]>) => ({ message: { statusCode, headers } }) as unknown as Parameters<typeof handler.canHandleAuthentication>[0];

    it("handles a 401 Negotiate challenge", () => {
      expect(handler.canHandleAuthentication(makeResponse(401, { "www-authenticate": "Negotiate" }))).toBe(true);
    });

    it("handles a 401 that offers Negotiate among multiple schemes", () => {
      expect(handler.canHandleAuthentication(makeResponse(401, { "www-authenticate": ["NTLM", "Negotiate"] }))).toBe(true);
    });

    it("ignores a 401 without a Negotiate offer", () => {
      expect(handler.canHandleAuthentication(makeResponse(401, { "www-authenticate": "Basic realm=tfs" }))).toBe(false);
    });

    it("ignores non-401 responses", () => {
      expect(handler.canHandleAuthentication(makeResponse(200, {}))).toBe(false);
    });

    it("retries the request with a minted Negotiate header", async () => {
      const drained = { message: { statusCode: 200, headers: {} }, readBody: jest.fn<() => Promise<string>>().mockResolvedValue("") };
      const requestRawWithCallback = jest.fn((info: unknown, _data: unknown, cb: (err: unknown, res: unknown) => void) => {
        cb(null, drained);
      });
      const httpClient = { requestRawWithCallback } as never;
      const requestInfo = {
        httpModule: {},
        parsedUrl: new URL("https://ado.company.local/tfs/DefaultCollection/_apis/projects"),
        options: { headers: { Accept: "application/json" } },
      } as never;

      const res = await handler.handleAuthentication(httpClient, requestInfo, "");

      expect(res).toBe(drained);
      const sentInfo = requestRawWithCallback.mock.calls[0][0] as { options: { headers: Record<string, string> } };
      expect(sentInfo.options.headers.Authorization).toBe("Negotiate BASE64-SPNEGO-TOKEN");
      expect(sentInfo.options.headers.Accept).toBe("application/json");
    });

    it("steps through multiple legs, feeding back the server's continuation token", async () => {
      // Mirrors Gallagher's TFS: a 401+continuation, then 200. Each Kerberos step
      // echoes the challenge so we can assert the server token was fed back in.
      mockStep.mockImplementation(async (challenge: string) => `TOKEN[${challenge}]`);

      const drain = () => jest.fn<() => Promise<string>>().mockResolvedValue("");
      const challenge401 = { message: { statusCode: 401, headers: { "www-authenticate": "Negotiate SRV-CONT-1" } }, readBody: drain() };
      const ok200 = { message: { statusCode: 200, headers: {} }, readBody: drain() };
      const responses = [challenge401, ok200];
      const requestRawWithCallback = jest.fn((_info: unknown, _data: unknown, cb: (err: unknown, res: unknown) => void) => {
        cb(null, responses.shift());
      });
      const httpClient = { requestRawWithCallback, isSsl: true } as never;
      const requestInfo = {
        httpModule: {},
        parsedUrl: new URL("https://ado.company.local/tfs/DefaultCollection/_apis/projects"),
        options: { headers: {} },
      } as never;

      const res = await handler.handleAuthentication(httpClient, requestInfo, "");

      expect(res).toBe(ok200);
      expect(requestRawWithCallback).toHaveBeenCalledTimes(2);
      expect(mockStep).toHaveBeenNthCalledWith(1, ""); // first leg starts the handshake
      expect(mockStep).toHaveBeenNthCalledWith(2, "SRV-CONT-1"); // second leg feeds the server token
      expect(challenge401.readBody).toHaveBeenCalled(); // intermediate 401 drained to free the socket
      const leg2 = requestRawWithCallback.mock.calls[1][0] as { options: { headers: Record<string, string> } };
      expect(leg2.options.headers.Authorization).toBe("Negotiate TOKEN[SRV-CONT-1]");
    });

    it("gives up when a 401 carries no continuation token", async () => {
      const noContinuation = { message: { statusCode: 401, headers: { "www-authenticate": "Negotiate" } }, readBody: jest.fn<() => Promise<string>>().mockResolvedValue("") };
      const requestRawWithCallback = jest.fn((_info: unknown, _data: unknown, cb: (err: unknown, res: unknown) => void) => {
        cb(null, noContinuation);
      });
      const httpClient = { requestRawWithCallback, isSsl: true } as never;
      const requestInfo = { httpModule: {}, parsedUrl: new URL("https://ado.company.local/_apis/projects"), options: { headers: {} } } as never;

      const res = await handler.handleAuthentication(httpClient, requestInfo, "");

      expect(res).toBe(noContinuation);
      expect(requestRawWithCallback).toHaveBeenCalledTimes(1);
    });
  });
});
