export function hostnameFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

export function normalizeClaimText(parts) {
  return parts.filter(Boolean).join(" ").toLowerCase();
}
