import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("@termix-ssh/plugin-sdk/frontend", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@termix-ssh/plugin-sdk/frontend")>()),
  usePluginApi: () => ({}),
  useTranslation: () => ({ t: (key: string) => `t:${key}` }),
}));
vi.mock("../../src/frontend/webauthn-api", () => ({
  createWebAuthnApi: () => ({
    list: async () => [
      { id: "a", name: "Laptop", deviceType: "singleDevice", backedUp: false },
      { id: "b", name: "Phone", deviceType: "multiDevice", backedUp: true },
    ],
  }),
}));

import { PasskeyEnrollment } from "../../src/frontend/PasskeyEnrollment";

describe("PasskeyEnrollment", () => {
  it("names the passkey type in words", async () => {
    render(<PasskeyEnrollment />);
    expect(await screen.findByText("t:singleDevice")).toBeTruthy();
    expect(screen.getByText("t:synced")).toBeTruthy();
  });
});
