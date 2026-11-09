import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";

/** Whether the Passkeys button also shows on the single sign-on page. */
export async function passkeysOnSsoPage(
  ctx: Pick<PluginContext, "settings">,
): Promise<boolean> {
  try {
    return (await ctx.settings.get<boolean>("passkeysOnSsoPage")) !== false;
  } catch {
    return true;
  }
}

/** Passwordless passkey sign in, on unless an admin turned it off. */
export async function passwordlessEnabled(
  ctx: Pick<PluginContext, "settings">,
): Promise<boolean> {
  try {
    return (await ctx.settings.get<boolean>("passwordlessLogin")) !== false;
  } catch {
    return true;
  }
}
