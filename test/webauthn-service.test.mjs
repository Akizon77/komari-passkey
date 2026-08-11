import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const core = require("../runtime/webauthn-core.cjs");

test("verifier generates protected ES256 WebAuthn options", async () => {
  assert.deepEqual(await core.dispatch("/health", {}), {});
  const config = {
    rpID: "example.test",
    rpName: "Komari",
    origins: ["https://example.test"],
    userVerification: "required",
    residentKey: "required",
    authenticatorAttachment: "platform",
    attestationType: "none",
    timeoutMs: 60000,
    allowSyncedCredentials: false,
  };
  const credential = {
    id: "Y3JlZGVudGlhbA",
    transports: ["internal"],
  };
  const registration = await core.dispatch("/registration/options", {
    config,
    user: {
      uuid: "a530e5f7-f4d1-4d7d-a9c9-59f4363f88a1",
      username: "Komari",
    },
    credentials: [credential],
  });

  assert.equal(registration.options.rp.id, "example.test");
  assert.equal(registration.options.authenticatorSelection.residentKey, "required");
  assert.equal(registration.options.authenticatorSelection.userVerification, "required");
  assert.equal(registration.options.authenticatorSelection.authenticatorAttachment, "platform");
  assert.equal(registration.options.excludeCredentials[0].id, credential.id);
  assert.deepEqual(registration.options.pubKeyCredParams, [{ alg: -7, type: "public-key" }]);

  const authentication = await core.dispatch("/authentication/options", {
    config,
    credentials: [credential],
  });

  assert.equal(authentication.options.rpId, "example.test");
  assert.equal(authentication.options.userVerification, "required");
  assert.equal(authentication.options.allowCredentials[0].id, credential.id);
});
