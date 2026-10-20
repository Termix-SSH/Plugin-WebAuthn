import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { PasskeyLoginButton } from "./PasskeyLoginButton";
import { PasskeyEnrollment } from "./PasskeyEnrollment";
import { SecurityKeyChallenge } from "./SecurityKeyChallenge";
import { SecurityKeyEnrollment } from "./SecurityKeyEnrollment";

export function activate(app: TermixApp): void {
  app.registerLoginMethod({
    id: "passkey",
    titleKey: "title",
    placement: "inline",
    component: PasskeyLoginButton,
    enrollment: PasskeyEnrollment,
  });
  app.registerSecondFactorUI({
    id: "security-key",
    titleKey: "securityKey.title",
    component: SecurityKeyChallenge,
    enrollment: SecurityKeyEnrollment,
  });
}
