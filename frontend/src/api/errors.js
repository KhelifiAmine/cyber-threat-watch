export function errorMessage(e, fallback = "Request failed.") {
  const detail = e?.response?.data?.detail;

  // Shape #1 — plain string detail (our HTTPException).
  if (typeof detail === "string") return detail;

  // Shape #2 — array of Pydantic 422 validation errors. Prefix each with the
  // offending field name so "password: ..." reads clearly.
  if (Array.isArray(detail)) {
    const messages = detail.map((d) => {
      if (typeof d === "string") return d;
      const field = Array.isArray(d?.loc) ? d.loc[d.loc.length - 1] : null;
      const msg = d?.msg || JSON.stringify(d);
      return field && field !== "body" ? `${field}: ${msg}` : msg;
    });
    return messages.join("; ");
  }

  // Single nested object with a message.
  if (detail && typeof detail === "object") {
    return detail.msg || JSON.stringify(detail);
  }

  // Network / no response — surface the axios message instead of the generic fallback.
  if (typeof e?.message === "string" && !e?.response) return e.message;

  return fallback;
}
