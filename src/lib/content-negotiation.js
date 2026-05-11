/**
 * Content negotiation helpers.
 * Distinguish between browser (HTML) and API (JSON) requests.
 */

export function isHtmlRequest(request) {
  const accept = request.headers.accept || "";
  return accept.includes("text/html");
}

export function isApiRequest(request) {
  return !isHtmlRequest(request);
}
