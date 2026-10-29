import { useEffect, useMemo, useState } from "react";
import { Fingerprint } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@termix-ssh/plugin-sdk/ui";
import {
  usePluginApi,
  useTranslation,
  type LoginMethodUIProps,
} from "@termix-ssh/plugin-sdk/frontend";
import { createWebAuthnApi, isPasskeySupported } from "./webauthn-api";

export function PasskeyLoginButton({
  disabled,
  submit,
  username,
}: LoginMethodUIProps) {
  const { t } = useTranslation();
  const pluginApi = usePluginApi();
  const api = useMemo(() => createWebAuthnApi(pluginApi), [pluginApi]);
  const [loading, setLoading] = useState(false);
  const [supported] = useState(isPasskeySupported);
  const [allowed, setAllowed] = useState<boolean | null>(null);
  useEffect(() => {
    if (!supported) return;
    let cancelled = false;
    void api.passwordlessEnabled().then((on) => {
      if (!cancelled) setAllowed(on);
    });
    return () => {
      cancelled = true;
    };
  }, [api, supported]);
  if (!supported || allowed !== true) return null;

  return (
    <Button
      type="button"
      variant="outline"
      onClick={async () => {
        setLoading(true);
        try {
          await submit(
            await api.passkeyAssertion(username?.trim() || undefined),
          );
        } catch (err: unknown) {
          const error = err as {
            name?: string;
            message?: string;
            response?: { data?: { error?: string } };
          };
          // Closing the browser prompt is not a failure worth a toast.
          if (error?.name === "NotAllowedError" || error?.name === "AbortError")
            return;
          toast.error(
            error?.response?.data?.error || error?.message || t("loginFailed"),
          );
        } finally {
          setLoading(false);
        }
      }}
      disabled={disabled || loading}
      className="w-full h-10 font-bold"
    >
      <span className="flex items-center gap-2">
        <Fingerprint className="size-4" />
        {t("signIn")}
      </span>
    </Button>
  );
}
