import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { PasskeyEnrollment } from "./PasskeyEnrollment";
import { SecurityKeyEnrollment } from "./SecurityKeyEnrollment";
import { setKeySteps, type KeySteps } from "./webauthn-api";

// Termix draws the sign in button and the security key step itself and runs
// the browser prompts; these screens only manage the person's keys.
export function activate(app: TermixApp): void {
  setKeySteps((app as { auth?: KeySteps }).auth ?? null);
  app.onDispose(() => setKeySteps(null));
  app.registerLoginMethod({
    id: "passkey",
    titleKey: "title",
    enrollment: PasskeyEnrollment,
  });
  app.registerSecondFactorUI({
    id: "security-key",
    titleKey: "securityKey.title",
    enrollment: SecurityKeyEnrollment,
  });
}
