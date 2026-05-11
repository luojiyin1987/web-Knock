export function getClientIp(request, { trustProxy = false } = {}) {
  if (trustProxy) {
    const forwarded = request.headers["x-forwarded-for"];

    if (forwarded) {
      return forwarded.split(",")[0].trim();
    }
  }

  return request.socket?.remoteAddress || "unknown";
}

export function normalizeIp(ip) {
  if (!ip || ip === "unknown") return ip;
  // Handle IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1
  if (ip.startsWith("::ffff:")) {
    return ip.slice(7);
  }
  return ip;
}
