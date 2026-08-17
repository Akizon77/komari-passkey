"use strict";

class TextEncoder {
  encode(value) {
    return Buffer.from(value, "utf8");
  }
}

class TextDecoder {
  decode(value) {
    return Buffer.from(value).toString("utf8");
  }
}

if (process.versions.node === "0.0.0-goja") {
  globalThis.TextEncoder = TextEncoder;
  globalThis.TextDecoder = TextDecoder;
}

const { createHash, randomBytes, verify } = require("node:crypto");

function debugLog(event, details) {
  if (details === undefined) {
    console.log("[komari-passkey][core]", event);
    return;
  }
  console.log("[komari-passkey][core]", event, details);
}

function objectKeys(value) {
  return value && typeof value === "object" ? Object.keys(value) : [];
}

function stringLength(value) {
  return typeof value === "string" ? value.length : -1;
}

function arrayLength(value) {
  return Array.isArray(value) ? value.length : -1;
}

function bytes(value) {
  return new Uint8Array(value);
}

function digestName(algorithm) {
  const name = typeof algorithm === "string" ? algorithm : algorithm.name;
  switch (name) {
    case "SHA-256":
      return "sha256";
    case "SHA-384":
      return "sha384";
    case "SHA-512":
      return "sha512";
    default:
      throw new Error(`Unsupported digest ${name}`);
  }
}

function bytesFromBase64URL(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  return bytes(Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/") + padding, "base64"));
}

function base64URLFromBytes(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function concatenate(parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function derLength(length) {
  if (length < 128) {
    return Uint8Array.of(length);
  }
  return Uint8Array.of(129, length);
}

function derInteger(value) {
  let offset = 0;
  while (offset < value.length - 1 && value[offset] === 0) {
    offset += 1;
  }
  const normalized = value.subarray(offset);
  const positive = normalized[0] & 128 ? Uint8Array.of(0, ...normalized) : normalized;
  return concatenate([Uint8Array.of(2), derLength(positive.length), positive]);
}

function derECDSASignature(signature) {
  const componentLength = signature.length / 2;
  const sequence = concatenate([
    derInteger(signature.subarray(0, componentLength)),
    derInteger(signature.subarray(componentLength)),
  ]);
  return concatenate([Uint8Array.of(48), derLength(sequence.length), sequence]);
}

const ecCurves = {
  "P-256": {
    coordinateLength: 32,
    publicKeyPrefix: "3059301306072a8648ce3d020106082a8648ce3d030107034200",
  },
  "P-384": {
    coordinateLength: 48,
    publicKeyPrefix: "3076301006072a8648ce3d020106052b81040022036200",
  },
  "P-521": {
    coordinateLength: 66,
    publicKeyPrefix: "30819b301006072a8648ce3d020106052b8104002303818600",
  },
};

function importECDSAPublicKey(format, keyData, algorithm) {
  const curve = ecCurves[algorithm.namedCurve];
  if (
    format !== "jwk" ||
    algorithm.name !== "ECDSA" ||
    keyData.kty !== "EC" ||
    keyData.crv !== algorithm.namedCurve ||
    !curve
  ) {
    throw new Error("Unsupported ECDSA public key");
  }
  const x = bytesFromBase64URL(keyData.x);
  const y = bytesFromBase64URL(keyData.y);
  if (x.length !== curve.coordinateLength || y.length !== curve.coordinateLength) {
    throw new Error("Invalid ECDSA public key");
  }
  const point = concatenate([Uint8Array.of(4), x, y]);
  const der = concatenate([bytes(Buffer.from(curve.publicKeyPrefix, "hex")), point]);
  const base64 = Buffer.from(der).toString("base64");
  return {
    curve: algorithm.namedCurve,
    publicKeyPEM: `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----\n`,
  };
}

if (process.versions.node === "0.0.0-goja") {
  globalThis.crypto = {
    getRandomValues(array) {
      array.set(randomBytes(array.length));
      return array;
    },
    subtle: {
      async digest(algorithm, data) {
        const hash = createHash(digestName(algorithm));
        hash.update(Buffer.from(bytes(data)));
        return bytes(hash.digest()).buffer;
      },
      async importKey(format, keyData, algorithm) {
        return importECDSAPublicKey(format, keyData, algorithm);
      },
      async verify(algorithm, key, signature, data) {
        if (algorithm.name !== "ECDSA" || !key.publicKeyPEM) {
          throw new Error("Unsupported signature algorithm");
        }
        return verify(
          digestName(algorithm.hash),
          Buffer.from(bytes(data)),
          key.publicKeyPEM,
          Buffer.from(derECDSASignature(bytes(signature))),
        );
      },
    },
  };
}

const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require("@simplewebauthn/server");

function randomID() {
  return base64URLFromBytes(randomBytes(24));
}

function attachment(value) {
  return value === "any" ? undefined : value;
}

function credentials(value) {
  debugLog("credentials:input", {
    isArray: Array.isArray(value),
    count: arrayLength(value),
  });
  return (value || []).map((credential) => ({
    id: credential.id,
    transports: credential.transports || undefined,
  }));
}

function requireUserVerification(config) {
  return config.userVerification === "required";
}

function acceptsCredential(config, deviceType) {
  return config.allowSyncedCredentials || deviceType === "singleDevice";
}

async function registrationOptions(body) {
  debugLog("registrationOptions:start", {
    bodyKeys: objectKeys(body),
    configKeys: objectKeys(body.config),
    userKeys: objectKeys(body.user),
    userUUIDLength: stringLength(body.user && body.user.uuid),
    usernameLength: stringLength(body.user && body.user.username),
    credentialCount: arrayLength(body.credentials),
  });
  const options = await generateRegistrationOptions({
    rpName: body.config.rpName,
    rpID: body.config.rpID,
    userName: body.user.username,
    userID: new TextEncoder().encode(body.user.uuid),
    userDisplayName: body.user.username,
    timeout: body.config.timeoutMs,
    attestationType: body.config.attestationType,
    excludeCredentials: credentials(body.credentials),
    authenticatorSelection: {
      residentKey: body.config.residentKey,
      userVerification: body.config.userVerification,
      authenticatorAttachment: attachment(body.config.authenticatorAttachment),
    },
    supportedAlgorithmIDs: [-7],
  });
  const result = { challengeId: randomID(), options };
  debugLog("registrationOptions:success", {
    challengeIDLength: result.challengeId.length,
    challengeLength: stringLength(options.challenge),
    optionKeys: objectKeys(options),
  });
  return result;
}

async function authenticationOptions(body) {
  debugLog("authenticationOptions:start", {
    bodyKeys: objectKeys(body),
    configKeys: objectKeys(body.config),
    credentialCount: arrayLength(body.credentials),
  });
  const options = await generateAuthenticationOptions({
    rpID: body.config.rpID,
    timeout: body.config.timeoutMs,
    userVerification: body.config.userVerification,
    allowCredentials: credentials(body.credentials),
  });
  const result = { challengeId: randomID(), options };
  debugLog("authenticationOptions:success", {
    challengeIDLength: result.challengeId.length,
    challengeLength: stringLength(options.challenge),
    optionKeys: objectKeys(options),
    allowCredentialCount: arrayLength(options.allowCredentials),
  });
  return result;
}

async function registrationVerification(body) {
  debugLog("registrationVerification:start", {
    bodyKeys: objectKeys(body),
    configKeys: objectKeys(body.config),
    responseKeys: objectKeys(body.response),
    responseResponseKeys: objectKeys(body.response && body.response.response),
    expectedChallengeLength: stringLength(body.expectedChallenge),
  });
  const verification = await verifyRegistrationResponse({
    response: body.response,
    expectedChallenge: body.expectedChallenge,
    expectedOrigin: body.config.origins,
    expectedRPID: body.config.rpID,
    requireUserVerification: requireUserVerification(body.config),
    supportedAlgorithmIDs: [-7],
  });
  if (!verification.verified) {
    debugLog("registrationVerification:not-verified");
    return { verified: false };
  }

  const info = verification.registrationInfo;
  debugLog("registrationVerification:verified", {
    credentialIDLength: stringLength(info.credential && info.credential.id),
    publicKeyLength: info.credential && info.credential.publicKey
      ? info.credential.publicKey.length
      : -1,
    counter: info.credential && info.credential.counter,
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
  });
  if (!acceptsCredential(body.config, info.credentialDeviceType)) {
    debugLog("registrationVerification:credential-rejected", {
      deviceType: info.credentialDeviceType,
    });
    return { verified: false, code: "synced_credential_not_allowed" };
  }

  const result = {
    verified: true,
    credential: {
      id: info.credential.id,
      publicKey: base64URLFromBytes(info.credential.publicKey),
      counter: info.credential.counter,
      transports: body.response.response.transports || [],
    },
    credentialDeviceType: info.credentialDeviceType,
    credentialBackedUp: info.credentialBackedUp,
  };
  debugLog("registrationVerification:success", {
    resultKeys: objectKeys(result),
    credentialKeys: objectKeys(result.credential),
    publicKeyLength: result.credential.publicKey.length,
  });
  return result;
}

async function authenticationVerification(body) {
  debugLog("authenticationVerification:start", {
    bodyKeys: objectKeys(body),
    configKeys: objectKeys(body.config),
    responseKeys: objectKeys(body.response),
    responseResponseKeys: objectKeys(body.response && body.response.response),
    credentialKeys: objectKeys(body.credential),
    credentialIDLength: stringLength(body.credential && body.credential.id),
    publicKeyLength: stringLength(body.credential && body.credential.publicKey),
    counter: body.credential && body.credential.counter,
    expectedChallengeLength: stringLength(body.expectedChallenge),
  });
  const verification = await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: body.expectedChallenge,
    expectedOrigin: body.config.origins,
    expectedRPID: body.config.rpID,
    credential: {
      id: body.credential.id,
      publicKey: bytesFromBase64URL(body.credential.publicKey),
      counter: body.credential.counter,
      transports: body.credential.transports || undefined,
    },
    requireUserVerification: requireUserVerification(body.config),
  });
  if (!verification.verified) {
    debugLog("authenticationVerification:not-verified");
    return { verified: false };
  }

  const info = verification.authenticationInfo;
  debugLog("authenticationVerification:verified", {
    credentialIDLength: stringLength(info.credentialID),
    newCounter: info.newCounter,
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
  });
  if (!acceptsCredential(body.config, info.credentialDeviceType)) {
    debugLog("authenticationVerification:credential-rejected", {
      deviceType: info.credentialDeviceType,
    });
    return { verified: false, code: "synced_credential_not_allowed" };
  }

  const result = {
    verified: true,
    credentialID: info.credentialID,
    newCounter: info.newCounter,
    credentialDeviceType: info.credentialDeviceType,
    credentialBackedUp: info.credentialBackedUp,
    sessionToken: base64URLFromBytes(randomBytes(32)),
  };
  debugLog("authenticationVerification:success", {
    resultKeys: objectKeys(result),
    sessionTokenLength: result.sessionToken.length,
  });
  return result;
}

async function dispatch(pathname, body) {
  debugLog("dispatch:start", {
    pathname,
    bodyKeys: objectKeys(body),
  });
  try {
    let result;
    switch (pathname) {
      case "/health":
        result = {};
        break;
      case "/registration/options":
        result = await registrationOptions(body);
        break;
      case "/registration/verify":
        result = await registrationVerification(body);
        break;
      case "/authentication/options":
        result = await authenticationOptions(body);
        break;
      case "/authentication/verify":
        result = await authenticationVerification(body);
        break;
      default:
        throw new Error("not_found");
    }
    debugLog("dispatch:success", {
      pathname,
      resultKeys: objectKeys(result),
      verified: result.verified,
    });
    return result;
  } catch (error) {
    console.error("[komari-passkey][core] dispatch failed:", {
      pathname,
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw error;
  }
}

module.exports = { dispatch };
