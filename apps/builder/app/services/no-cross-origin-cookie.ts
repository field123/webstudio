import { json } from "@remix-run/server-runtime";

/**
 * https://kevincox.ca/2024/08/24/cors/
 *
 * The function is specifically needed to handle "simple" CORS requests,
 * which are more prone to bypassing the stricter CORS preflight checks.
 * By clearing cookies from these cross-origin requests,
 * it reduces the risk of CSRF attacks and other vulnerabilities associated with simple CORS requests.
 *
 * Warning: There is no combination of Access-Control-Allow-* headers that you can set that solves simple requests,
 * they are made before any policy is checked. You need to handle them in another way.
 * Do not try to fix this by setting a CORS policy
 **/
export const preventCrossOriginCookie = (
  request: Request,
  throwError: boolean = true
) => {
  const secFetchSite = request.headers.get("sec-fetch-site");
  const secFetchMode = request.headers.get("sec-fetch-mode");
  const secFetchDest = request.headers.get("sec-fetch-dest");
  const method = request.method;
  const url = request.url;

  if (secFetchSite === "same-origin") {
    // Same origin, OK
    return;
  }

  if (secFetchMode === "navigate" && method === "GET") {
    // GET requests shouldn't mutate state so this is safe.
    return;
  }

  // Allow cross-site document requests (e.g., clicking links from Vercel dashboard)
  // These are legitimate navigation requests that should be allowed
  if (
    method === "GET" &&
    secFetchDest === "document" &&
    (secFetchMode === "cors" || secFetchMode === "navigate")
  ) {
    // This handles cases like:
    // - Clicking deployment URLs from Vercel dashboard
    // - Direct navigation from external sites
    // - Bookmarks and direct URL access
    return;
  }

  request.headers.delete("cookie");

  if (
    request.headers.has("Authorization") ||
    request.headers.has("x-auth-token")
  ) {
    // Do not throw an error if the request has an Authorization or x-auth-token header.
    // In that case, it is not a simple CORS request and will be prevented by a preflight check.
    return;
  }

  if (throwError) {
    console.error(`Cross-origin request to ${url} blocked`, {
      secFetchSite,
      secFetchMode,
      secFetchDest,
      method,
      referer: request.headers.get("referer"),
      reason: "Not a legitimate document navigation request",
    });

    // allow service calls
    throw json(
      {
        message: `Cross-origin request to ${url}`,
      },
      {
        status: 403,
        statusText: "Forbidden",
      }
    );
  }
};
