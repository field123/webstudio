import { Authenticator } from "remix-auth";
import { FormStrategy } from "remix-auth-form";
import { GitHubStrategy, type GitHubProfile } from "remix-auth-github";
import { GoogleStrategy, type GoogleProfile } from "remix-auth-google";
import * as db from "~/shared/db";
import { sessionStorage } from "~/services/session.server";
import { AUTH_PROVIDERS } from "~/shared/session";
import { authCallbackPath, isBuilder } from "~/shared/router-utils";
import { getUserById } from "~/shared/db/user.server";
import env from "~/env/env.server";
import { builderAuthenticator } from "./builder-auth.server";
import { staticEnv } from "~/env/env.static.server";
import type { SessionData } from "./auth.server.utils";
import { createContext } from "~/shared/context.server";
import { storeEPToken } from "./elastic-path-token.server";

const transformRefToAlias = (input: string) => {
  const rawAlias = input.endsWith(".staging") ? input.slice(0, -8) : input;

  return rawAlias
    .replace(/[^a-zA-Z0-9_-]/g, "") // Remove all characters except a-z, A-Z, 0-9, _ and -
    .toLowerCase() // Convert to lowercase
    .replace(/_/g, "-") // Replace underscores with hyphens
    .replace(/-+/g, "-"); // Replace multiple hyphens with a single hyphen
};

export const callbackOrigin =
  env.DEPLOYMENT_ENVIRONMENT === "production"
    ? env.DEPLOYMENT_URL
    : env.DEPLOYMENT_ENVIRONMENT === "staging" ||
        env.DEPLOYMENT_ENVIRONMENT === "development"
      ? `https://${transformRefToAlias(staticEnv.GITHUB_REF_NAME ?? "main")}.${env.DEPLOYMENT_ENVIRONMENT}.webstudio.is`
      : `https://wstd.dev:${env.PORT || 5173}`;

const strategyCallback = async ({
  profile,
  request,
}: {
  profile: GitHubProfile | GoogleProfile;
  request: Request;
}) => {
  const context = await createContext(request);

  try {
    const user = await db.user.createOrLoginWithOAuth(context, profile);
    return { userId: user.id, createdAt: Date.now() };
  } catch (error) {
    if (error instanceof Error) {
      console.error({
        error,
        extras: {
          loginMethod: AUTH_PROVIDERS.LOGIN_DEV,
        },
      });
    }
    throw error;
  }
};

// Create an instance of the authenticator, pass a generic with what
// strategies will return and will store in the session
export const authenticator = new Authenticator<SessionData>(sessionStorage, {
  throwOnError: true,
});

if (env.GH_CLIENT_ID && env.GH_CLIENT_SECRET) {
  const github = new GitHubStrategy(
    {
      clientID: env.GH_CLIENT_ID,
      clientSecret: env.GH_CLIENT_SECRET,
      callbackURL: `${callbackOrigin}${authCallbackPath({ provider: "github" })}`,
    },
    strategyCallback
  );
  authenticator.use(github, "github");
}

if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
  const google = new GoogleStrategy(
    {
      clientID: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${callbackOrigin}${authCallbackPath({ provider: "google" })}`,
    },
    strategyCallback
  );
  authenticator.use(google, "google");
}

// Elastic Path Strategy
const elasticPath = new FormStrategy(async ({ form, request }) => {
  const email = form.get("email");
  const password = form.get("password");

  if (!email || typeof email !== "string") {
    throw new Error("Email is required");
  }

  if (!password || typeof password !== "string") {
    throw new Error("Password is required");
  }

  try {
    const data = new URLSearchParams({
      grant_type: "password",
      username: email,
      password,
    });

    // Authenticate with Elastic Path
    const response = await fetch(`${env.ELASTIC_PATH_URL}/oauth/access_token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: data,
    });

    if (!response.ok) {
      throw new Error(`Authentication failed: ${response.statusText}`);
    }

    const tokenResponse = (await response.json()) as {
      access_token?: string;
      refresh_token?: string;
      identifier?: "password";
      expires?: number;
      expires_in?: number;
      token_type?: "Bearer";
    };

    if (!tokenResponse.token_type) {
      throw new Error(JSON.stringify(tokenResponse));
    }

    if (!tokenResponse.access_token) {
      throw new Error("No access token received");
    }

    const context = await createContext(request);

    // Create or login user in the database
    const user = await db.user.createOrLoginWithElasticPath(context, {
      email: email,
      username: email,
      image: "",
      provider: "elastic-path",
    });

    // Store the EP access token in a separate session
    await storeEPToken(request, {
      accessToken: tokenResponse.access_token,
      tokenType: tokenResponse.token_type,
      expiresIn: tokenResponse.expires_in,
      userId: user.id,
    });

    return {
      userId: user.id,
      createdAt: Date.now(),
    };
  } catch (error) {
    if (error instanceof Error) {
      console.error({
        error,
        extras: {
          loginMethod: "elastic-path",
        },
      });
    }
    throw error;
  }
});

authenticator.use(elasticPath, "elastic-path");

if (env.DEV_LOGIN === "true") {
  authenticator.use(
    new FormStrategy(async ({ form, request }) => {
      const secretValue = form.get("secret");

      if (secretValue == null) {
        throw new Error("Secret is required");
      }

      const [secret, email = "hello@webstudio.is"] = secretValue
        .toString()
        .split(":");

      if (secret === env.AUTH_SECRET) {
        try {
          const context = await createContext(request);

          const user = await db.user.createOrLoginWithDev(context, email);
          return {
            userId: user.id,
            createdAt: Date.now(),
          };
        } catch (error) {
          if (error instanceof Error) {
            console.error({
              error,
              extras: {
                loginMethod: AUTH_PROVIDERS.LOGIN_DEV,
              },
            });
          }
          throw error;
        }
      }

      throw new Error("Secret is incorrect");
    }),
    "dev"
  );
}

export const findAuthenticatedUser = async (request: Request) => {
  const user = isBuilder(request)
    ? await builderAuthenticator.isAuthenticated(request)
    : await authenticator.isAuthenticated(request);

  if (user == null) {
    return null;
  }
  const context = await createContext(request);

  try {
    return await getUserById(context, user.userId);
  } catch (error) {
    return null;
  }
};
