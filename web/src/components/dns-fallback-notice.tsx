import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api } from "../api/endpoints";

export function DNSFallbackNotice({ running }: { running: boolean }) {
  const { t } = useTranslation();
  const dns = useQuery({
    queryKey: ["dns"],
    queryFn: ({ signal }) => api.dns(signal),
    enabled: running,
    // Upstream selection is fixed for each capture run; do not poll DNS history.
    refetchInterval: false,
  });
  if (!running || !dns.data?.status.public_fallback) return null;
  return (
    <output className="inlineNote">
      {t("resolvers.publicFallback")}{" "}
      <Link to="/settings" search={{ section: "resolvers" }}>
        {t("readiness.openDNS")}
      </Link>
    </output>
  );
}
