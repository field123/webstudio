import { createCookieSessionStorage } from "@remix-run/node";
import env from "~/env/env.server";
import { getSessionCookieNameVersion } from "./auth.server.utils";

// Separate session storage for EP tokens
export const epTokenSessionStorage = createCookieSessionStorage({
  cookie: {
    name: `__Host-_ep_token_${getSessionCookieNameVersion()}`,
    sameSite: "lax",
    path: "/",
    httpOnly: true,
    secrets: [env.AUTH_SECRET || "fallback-secret-for-dev"],
    secure: process.env.NODE_ENV === "production",
    maxAge: 60 * 60 * 24 * 7, // 7 days
  },
});

export type EPTokenData = {
  accessToken: string;
  tokenType?: string;
  expiresIn?: number;
  userId: string;
};

export const storeEPToken = async (
  request: Request,
  tokenData: EPTokenData
): Promise<string> => {
  const session = await epTokenSessionStorage.getSession(
    request.headers.get("Cookie")
  );

  session.set("epToken", tokenData);

  return await epTokenSessionStorage.commitSession(session);
};

export const getEPToken = async (
  request: Request
): Promise<EPTokenData | null> => {
  const session = await epTokenSessionStorage.getSession(
    request.headers.get("Cookie")
  );

  return session.get("epToken") || null;
};

export const clearEPToken = async (request: Request): Promise<string> => {
  const session = await epTokenSessionStorage.getSession(
    request.headers.get("Cookie")
  );

  return await epTokenSessionStorage.destroySession(session);
};

// Utility function to get EP token for authenticated user
export const getEPTokenForUser = async (
  request: Request,
  userId: string
): Promise<string | null> => {
  const tokenData = await getEPToken(request);

  if (!tokenData || tokenData.userId !== userId) {
    return null;
  }

  return tokenData.accessToken;
};
