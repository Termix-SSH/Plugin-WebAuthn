import { useState } from "react";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@termix-ssh/plugin-sdk/ui";
import {
  useTranslation,
  type SecondFactorUIProps,
} from "@termix-ssh/plugin-sdk/frontend";
import { securityKeyAssertion } from "./webauthn-api";

/** The security key step after a password. */
export function SecurityKeyChallenge({
  disabled,
  verify,
  challenge,
  cancel,
}: SecondFactorUIProps) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true);
    try {
      await verify(await securityKeyAssertion(await challenge()));
    } catch (err: unknown) {
      const error = err as { name?: string; message?: string };
      // Closing the browser prompt is not a failure worth a toast.
      if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
        return;
      }
      toast.error(error?.message || t("securityKey.failed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">{t("securityKey.prompt")}</p>
      <Button
        type="button"
        onClick={() => void run()}
        disabled={disabled || loading}
        className="w-full h-10 font-bold"
      >
        <span className="flex items-center gap-2">
          <KeyRound className="size-4" />
          {t("securityKey.use")}
        </span>
      </Button>
      <Button
        type="button"
        variant="outline"
        onClick={cancel}
        disabled={loading}
        className="w-full"
      >
        {t("common.cancel")}
      </Button>
    </div>
  );
}
