import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";

import * as plugin from "../../src/frontend/index";
import {
  createWebAuthnApi,
  setKeySteps,
} from "../../src/frontend/webauthn-api";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;
const webauthn = vi.fn(async () => ({ ok: true }) as Record<string, unknown>);

beforeEach(() => {
  webauthn.mockClear();
  setKeySteps({ webauthn });
});

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
  setKeySteps(null);
});

describe(`${manifest.id} activate`, () => {
  it("registers only the enrolment screens; Termix draws the sign in steps", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.loginMethods()).toEqual(["passkey"]);
    expect(rendered.registered.secondFactors()).toEqual(["security-key"]);
  });

  it("adds a key through Termix before turning the step on", async () => {
    let enabled = false;
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: {
        get: vi.fn(async () => ({ data: { enabled, keys: enabled ? 1 : 0 } })),
        post: vi.fn(async (path: string) => {
          if (path === "second-factor/enable") enabled = true;
          return { data: {} };
        }),
        delete: vi.fn(),
      } as never,
    });
    setKeySteps({ webauthn });
    rendered.renderEnrollment("security-key");
    fireEvent.click(await screen.findByText(locales.securityKey.addKey));
    expect(await screen.findByText(locales.securityKey.on)).toBeTruthy();
    expect(webauthn).toHaveBeenCalledWith("register", {
      name: locales.securityKey.keyName,
      userVerification: "discouraged",
    });
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

  it("removes the screens on deactivate", async () => {
    const app = await renderWithApp(plugin, { manifest, locales });
    await app.deactivate();
    expect(app.registered.loginMethods()).toEqual([]);
    expect(app.registered.secondFactors()).toEqual([]);
  });
});

describe("webauthn api", () => {
  const status = (enabled: boolean) =>
    vi.fn(async () => ({ data: { enabled, keys: 1 } }));

  it("registers through the shell's key step", async () => {
    await createWebAuthnApi({} as never).register("Key", "required");
    expect(webauthn).toHaveBeenCalledWith("register", {
      name: "Key",
      userVerification: "required",
    });
  });

  it("says why a key step failed", async () => {
    webauthn.mockResolvedValueOnce({ ok: false, error: "Expired" });
    await expect(
      createWebAuthnApi({} as never).register("Key", "required"),
    ).rejects.toThrow("Expired");
  });

  it("treats a closed browser prompt as cancelled", async () => {
    webauthn.mockResolvedValueOnce({ ok: false, closed: true });
    await expect(
      createWebAuthnApi({} as never).register("Key", "required"),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  it("asks for a tap to remove a key while the step is on", async () => {
    const remove = vi.fn();
    await createWebAuthnApi({
      get: status(true),
      delete: remove,
    } as never).remove("p1");
    expect(webauthn).toHaveBeenCalledWith("remove-key", {
      credentialId: "p1",
    });
    expect(remove).not.toHaveBeenCalled();
  });

  it("removes a key directly while the step is off", async () => {
    const remove = vi.fn(async () => ({ data: {} }));
    await createWebAuthnApi({
      get: status(false),
      delete: remove,
    } as never).remove("p1");
    expect(remove).toHaveBeenCalledWith("credentials/p1");
    expect(webauthn).not.toHaveBeenCalled();
  });

  it("turns the step off only with a tap", async () => {
    await createWebAuthnApi({} as never).setFactor(false);
    expect(webauthn).toHaveBeenCalledWith("disable-factor", {});
  });

  it("refuses key steps on a Termix without them", async () => {
    setKeySteps(null);
    await expect(
      createWebAuthnApi({} as never).register("Key", "required"),
    ).rejects.toThrow(/can't run key steps/);
  });
});
