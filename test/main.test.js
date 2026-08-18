import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createHandler, hashEbayUserId } from "../src/main.js";

const APPWRITE_ENDPOINT = "https://appwrite.example/v1";
const EBAY_USER_ID = "immutable-ebay-user-id";
const ENDPOINT_URL =
  "https://keepflip-deletion.example.appwrite.run/webhooks/ebay/account-deletion";

function jsonResponse(status, body = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function emptyResponse(status = 204) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => "",
  };
}

function responseSink() {
  let response;
  return {
    res: {
      empty() {
        response = { kind: "empty", statusCode: 204 };
        return response;
      },
      json(body, statusCode = 200) {
        response = { body, kind: "json", statusCode };
        return response;
      },
    },
    response: () => response,
  };
}

function configureEnvironment() {
  process.env.APPWRITE_FUNCTION_API_ENDPOINT = APPWRITE_ENDPOINT;
  process.env.APPWRITE_FUNCTION_PROJECT_ID = "keepflip";
  process.env.EBAY_OAUTH_ENVIRONMENT = "sandbox";
  process.env.EBAY_SANDBOX_CLIENT_ID = "sandbox-client-id";
  process.env.EBAY_SANDBOX_CLIENT_SECRET = "sandbox-client-secret";
  process.env.EBAY_PRODUCTION_CLIENT_ID = "production-client-id";
  process.env.EBAY_PRODUCTION_CLIENT_SECRET = "production-client-secret";
  process.env.EBAY_DELETION_ENDPOINT_URL = ENDPOINT_URL;
  process.env.EBAY_DELETION_VERIFICATION_TOKEN = "a".repeat(48);
  process.env.EBAY_USER_ID_HMAC_KEY = Buffer.alloc(32, 19).toString("base64");
  process.env.EBAY_NOTIFICATION_APP_SCOPES =
    "https://api.ebay.com/oauth/api_scope";
}

function deletionPayload(userId = EBAY_USER_ID) {
  return JSON.stringify({
    metadata: {
      deprecated: false,
      schemaVersion: "1.0",
      topic: "MARKETPLACE_ACCOUNT_DELETION",
    },
    notification: {
      data: { eiasToken: "legacy-token-not-stored", userId, username: "not-stored" },
      notificationId: "notification-id",
    },
  });
}

function signedHeader({ body, keyId, privateKey }) {
  const signer = createSign("sha1");
  signer.update(body, "utf8");
  signer.end();
  const packed = {
    alg: "ECDSA",
    digest: "SHA1",
    kid: keyId,
    signature: signer.sign(privateKey).toString("base64"),
  };
  return Buffer.from(JSON.stringify(packed), "utf8").toString("base64");
}

test("returns eBay's exact SHA-256 verification challenge response", async () => {
  configureEnvironment();
  const handler = createHandler({
    fetchImpl: async () => {
      throw new Error("The verification challenge must not contact external services.");
    },
  });
  const sink = responseSink();
  const challengeCode = "ebay-challenge-code";

  await handler({
    req: {
      method: "GET",
      path: "/webhooks/ebay/account-deletion",
      query: { challenge_code: challengeCode },
    },
    res: sink.res,
  });

  assert.equal(sink.response().kind, "json");
  assert.equal(sink.response().statusCode, 200);
  assert.equal(
    sink.response().body.challengeResponse,
    createHash("sha256")
      .update(challengeCode)
      .update(process.env.EBAY_DELETION_VERIFICATION_TOKEN)
      .update(ENDPOINT_URL)
      .digest("hex"),
  );
});

test("rejects an unsigned notification without accessing Appwrite or eBay", async () => {
  configureEnvironment();
  let fetchCalled = false;
  const handler = createHandler({
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("Unexpected request");
    },
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyText: deletionPayload(),
      headers: { "x-appwrite-key": "dynamic-key" },
      method: "POST",
      path: "/webhooks/ebay/account-deletion",
    },
    res: sink.res,
  });

  assert.equal(sink.response().kind, "json");
  assert.equal(sink.response().statusCode, 412);
  assert.equal(fetchCalled, false);
});

test("verifies a signed event, deletes only its matched connection, and accepts replay", async () => {
  configureEnvironment();
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const body = deletionPayload();
  const keyId = "sandbox-validation-key";
  const signature = signedHeader({ body, keyId, privateKey });
  const publicKeyBase64 = publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64");
  const deletedRowIds = [];
  const logs = [];
  const errors = [];
  let listCalls = 0;

  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      const requestUrl = String(url);

      if (requestUrl === "https://api.sandbox.ebay.com/identity/v1/oauth2/token") {
        return jsonResponse(200, { access_token: "application-token", expires_in: 7_200 });
      }
      if (
        requestUrl ===
        "https://api.sandbox.ebay.com/commerce/notification/v1/public_key/sandbox-validation-key"
      ) {
        assert.equal(options.headers.Authorization, "Bearer application-token");
        return jsonResponse(200, { key: publicKeyBase64 });
      }
      if (
        requestUrl.startsWith(
          `${APPWRITE_ENDPOINT}/tablesdb/keepflip/tables/ebay_connections/rows?`,
        )
      ) {
        const queries = new URL(requestUrl).searchParams.getAll("queries[]");
        assert.ok(
          queries.includes(
            `equal("ebayUserIdHmac",["${hashEbayUserId(EBAY_USER_ID)}"])`,
          ),
        );
        listCalls += 1;
        return jsonResponse(200, {
          rows: listCalls === 1 ? [{ $id: "matched-connection" }] : [],
          total: listCalls === 1 ? 1 : 0,
        });
      }
      if (
        requestUrl.endsWith(
          "/tablesdb/keepflip/tables/ebay_connections/rows/matched-connection",
        ) && options.method === "DELETE"
      ) {
        deletedRowIds.push("matched-connection");
        return emptyResponse();
      }
      throw new Error(`Unexpected request: ${requestUrl}`);
    },
  });

  const firstSink = responseSink();
  await handler({
    error: (message) => errors.push(message),
    log: (message) => logs.push(message),
    req: {
      bodyText: body,
      headers: {
        "x-appwrite-key": "dynamic-key",
        "x-ebay-signature": signature,
      },
      method: "POST",
      path: "/webhooks/ebay/account-deletion",
    },
    res: firstSink.res,
  });

  assert.deepEqual(firstSink.response(), { kind: "empty", statusCode: 204 });
  assert.deepEqual(deletedRowIds, ["matched-connection"]);

  const replaySink = responseSink();
  await handler({
    error: (message) => errors.push(message),
    log: (message) => logs.push(message),
    req: {
      bodyText: body,
      headers: {
        "x-appwrite-key": "dynamic-key",
        "x-ebay-signature": signature,
      },
      method: "POST",
      path: "/webhooks/ebay/account-deletion",
    },
    res: replaySink.res,
  });

  assert.deepEqual(replaySink.response(), { kind: "empty", statusCode: 204 });
  assert.deepEqual(deletedRowIds, ["matched-connection"]);
  assert.equal(listCalls, 3);
  assert.equal(JSON.stringify(logs).includes(EBAY_USER_ID), false);
  assert.equal(JSON.stringify(errors).includes(EBAY_USER_ID), false);
  assert.equal(JSON.stringify(firstSink.response()).includes(EBAY_USER_ID), false);
});
