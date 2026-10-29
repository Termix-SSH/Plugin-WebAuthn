import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";

const browser = vi.hoisted(() => ({
  startAuthentication: vi.fn(async () => ({ id: "cred-1" })),
  startRegistration: vi.fn(async () => ({ id: "cred-1" })),
  browserSupportsWebAuthn: vi.fn(() => true),
}));
vi.mock("@simplewebauthn/browser", () => browser);

import * as plugin from "../../src/frontend/index";
import { createWebAuthnApi } from "../../src/frontend/webauthn-api";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

beforeEach(() => {
  vi.clearAllMocks();
  browser.browserSupportsWebAuthn.mockReturnValue(true);
});

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

describe(`${manifest.id} activate`, () => {
  it("registers the passkey login method", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.loginMethods()).toEqual(["passkey"]);
  });

  it("runs the security key step with the challenge core hands over", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.secondFactors()).toEqual(["security-key"]);
    const verify = vi.fn(async () => {});
    const challenge = vi.fn(async () => ({ challenge: "abc" }));
    rendered.renderSecondFactor("security-key", { verify, challenge });
    fireEvent.click(screen.getByText(locales.securityKey.use));
    await waitFor(() =>
      expect(verify).toHaveBeenCalledWith({ response: { id: "cred-1" } }),
    );
    expect(browser.startAuthentication).toHaveBeenCalledWith({
      optionsJSON: { challenge: "abc" },
    });
  });

  it("adds a key before turning the step on", async () => {
    const post = vi.fn(async (path: string) =>
      path === "register/options"
        ? { data: { options: {}, challengeId: "c1" } }
        : { data: {} },
    );
    let enabled = false;
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: {
        get: vi.fn(async () => ({ data: { enabled, keys: enabled ? 1 : 0 } })),
        post: vi.fn(async (path: string) => {
          if (path === "second-factor/enable") enabled = true;
          return post(path);
        }),
        delete: vi.fn(),
      } as never,
    });
    rendered.renderEnrollment("security-key");
    fireEvent.click(await screen.findByText(locales.securityKey.addKey));
    expect(await screen.findByText(locales.securityKey.on)).toBeTruthy();
    expect(browser.startRegistration).toHaveBeenCalled();
  });

  it("runs the ceremony and submits the assertion", async () => {
    const post = vi.fn(async () => ({
      data: { options: { challenge: "abc" }, challengeId: "chal-1" },
    }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { post } as never,
    });
    const submit = vi.fn(async () => {});
    rendered.renderLoginMethod("passkey", { submit, username: " luke " });
    fireEvent.click(await screen.findByText(locales.signIn));
    await waitFor(() =>
      expect(submit).toHaveBeenCalledWith({
        challengeId: "chal-1",
        response: { id: "cred-1" },
      }),
    );
    expect(post).toHaveBeenCalledWith("authenticate/options", {
      username: "luke",
    });
  });

  it("hides the button when an admin turned passkey sign in off", async () => {
    const get = vi.fn(async () => ({ data: { passwordless: false } }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get, post: vi.fn() } as never,
    });
    rendered.renderLoginMethod("passkey");
    await waitFor(() => expect(get).toHaveBeenCalledWith("login-options"));
    expect(screen.queryByText(locales.signIn)).toBeNull();
  });

  it("draws nothing where the browser has no WebAuthn", async () => {
    browser.browserSupportsWebAuthn.mockReturnValue(false);
    rendered = await renderWithApp(plugin, { manifest, locales });
    rendered.renderLoginMethod("passkey");
    expect(screen.queryByText(locales.signIn)).toBeNull();
  });

  it("lists passkeys in the enrolment section", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: {
        get: vi.fn(async () => ({
          data: {
            credentials: [
              {
                id: "p1",
                name: "Laptop",
                backedUp: true,
                transports: [],
                userVerification: "preferred",
                createdAt: "",
              },
            ],
          },
        })),
      } as never,
    });
    rendered.renderEnrollment("passkey");
    expect(await screen.findByText("Laptop")).toBeTruthy();
  });

  it("removes the method on deactivate", async () => {
    const app = await renderWithApp(plugin, { manifest, locales });
    await app.deactivate();
    expect(app.registered.loginMethods()).toEqual([]);
  });
});

describe("webauthn api", () => {
  it("omits the username so discoverable passkeys work", async () => {
    const post = vi.fn(async () => ({
      data: { options: { challenge: "abc" }, challengeId: "chal-2" },
    }));
    await createWebAuthnApi({ post } as never).passkeyAssertion();
    expect(post).toHaveBeenCalledWith("authenticate/options", {});
  });

  it("registers through options then verify", async () => {
    const post = vi
      .fn()
      .mockResolvedValueOnce({
        data: { options: { challenge: "r" }, challengeId: "reg-1" },
      })
      .mockResolvedValueOnce({ data: { success: true } });
    await createWebAuthnApi({ post } as never).register("Key", "required");
    expect(post).toHaveBeenNthCalledWith(1, "register/options", {
      userVerification: "required",
    });
    expect(post).toHaveBeenNthCalledWith(2, "register/verify", {
      challengeId: "reg-1",
      name: "Key",
      response: { id: "cred-1" },
    });
  });
});
