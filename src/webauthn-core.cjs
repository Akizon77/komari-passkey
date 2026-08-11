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
  return { challengeId: randomID(), options };
}

async function authenticationOptions(body) {
  const options = await generateAuthenticationOptions({
    rpID: body.config.rpID,
    timeout: body.config.timeoutMs,
    userVerification: body.config.userVerification,
    allowCredentials: credentials(body.credentials),
  });
  return { challengeId: randomID(), options };
}

async function registrationVerification(body) {
  const verification = await verifyRegistrationResponse({
    response: body.response,
    expectedChallenge: body.expectedChallenge,
    expectedOrigin: body.config.origins,
    expectedRPID: body.config.rpID,
    requireUserVerification: requireUserVerification(body.config),
    supportedAlgorithmIDs: [-7],
  });
  if (!verification.verified) {
    return { verified: false };
  }

  const info = verification.registrationInfo;
  if (!acceptsCredential(body.config, info.credentialDeviceType)) {
    return { verified: false, code: "synced_credential_not_allowed" };
  }

  return {
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
}

async function authenticationVerification(body) {
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
    return { verified: false };
  }

  const info = verification.authenticationInfo;
  if (!acceptsCredential(body.config, info.credentialDeviceType)) {
    return { verified: false, code: "synced_credential_not_allowed" };
  }

  return {
    verified: true,
    credentialID: info.credentialID,
    newCounter: info.newCounter,
    credentialDeviceType: info.credentialDeviceType,
    credentialBackedUp: info.credentialBackedUp,
    sessionToken: base64URLFromBytes(randomBytes(32)),
  };
}

async function dispatch(pathname, body) {
  switch (pathname) {
    case "/health":
      return {};
    case "/registration/options":
      return registrationOptions(body);
    case "/registration/verify":
      return registrationVerification(body);
    case "/authentication/options":
      return authenticationOptions(body);
    case "/authentication/verify":
      return authenticationVerification(body);
    default:
      throw new Error("not_found");
  }
}

module.exports = { dispatch };
