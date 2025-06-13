import { Button, Flex, InputField, theme } from "@webstudio-is/design-system";
import { useState } from "react";
import { authPath } from "~/shared/router-utils";

export const ElasticPathLogin = () => {
  const [show, setShow] = useState(false);

  if (show) {
    return (
      <form
        method="post"
        action={authPath({ provider: "elastic-path" })}
        style={{ display: "contents" }}
      >
        <Flex direction="column" gap="2">
          <InputField
            name="email"
            type="email"
            required
            autoFocus
            placeholder="Email"
            css={{ width: "100%" }}
          />
          <InputField
            name="password"
            type="password"
            required
            placeholder="Password"
            css={{ width: "100%" }}
          />
          <Button type="submit" css={{ height: theme.spacing[15] }}>
            Sign in with Elastic Path
          </Button>
        </Flex>
      </form>
    );
  }

  return (
    <Button
      onClick={() => setShow(true)}
      color="neutral"
      css={{ height: theme.spacing[15] }}
    >
      Sign in with Elastic Path
    </Button>
  );
};
