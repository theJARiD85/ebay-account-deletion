import { createHash, createHmac, createPublicKey, createVerify } from "node:crypto";

const APPWRITE_DATABASE_ID = "keepflip";
const CONNECTIONS_TABLE_ID = "ebay_connections";
const DELETION_PATH = "/webhooks/ebay/account-deletion";
const PUBLIC_KEY_CACHE_TTL_MS = 60 * 60 * 1_000;
const APP_TOKEN_CACHE_SAFETY_WINDOW_MS = 60 * 1_000;
const MAX_NOTIFICATION_BYTES = 1_000_000;
const MAX_DELETION_BATCHES = 100;

const appTokenCache = new Map();
const publicKeyCache = new Map();

export class RequestError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.name = "RequestError";
    this.statusCode = statusCode;
  }
}

class SignatureError extends RequestError {
  constructor() {
    super("The eBay notification signature could not be verified.", 412);
    this.name = "SignatureError";
  }
}

function cleanText(value, maximumLength = 2_000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maximumLength);
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";

  const expected = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== expected) continue;
    return cleanText(Array.isArray(value) ? value[0] : value, 16_000);
  }

  return "";
}

function getRequestPath(req) {
  const providedPath = cleanText(req?.path, 500);
  if (providedPath) {
    try {
      return new URL(providedPath, "https://keepflip.invalid").pathname;
    } catch {
      return "/";
    }
  }

  const requestUrl = cleanText(req?.url, 8_000);
  if (requestUrl) {
    try {
      return new URL(requestUrl, "https://keepflip.invalid").pathname;
    } catch {
      return "/";
    }
  }

  return "/";
}

function queryValue(req, key) {
  const parsedQuery = req?.query;
  if (parsedQuery && typeof parsedQuery === "object") {
    const value = parsedQuery[key];
    const first = Array.isArray(value) ? value[0] : value;
    const cleaned = cleanText(first, 8_000);
    if (cleaned) return cleaned;
  }

  const queryString = cleanText(req?.queryString, 8_000);
  if (queryString) {
    return cleanText(new URLSearchParams(queryString).get(key), 8_000);
  }

  const requestUrl = cleanText(req?.url, 8_000);
  if (requestUrl) {
    try {
      return cleanText(
        new URL(requestUrl, "https://keepflip.invalid").searchParams.get(key),
        8_000,
      );
    } catch {
      return "";
    }
  }

  return "";
}

function requireEnvironment(name) {
  const value = cleanText(process.env[name], 8_000);
  if (!value) {
    throw new RequestError(
      `KeepFlip's eBay deletion endpoint is missing the ${name} Function variable.`,
      500,
    );
  }
  return value;
}

function ebayEnvironment() {
  const value = cleanText(process.env.EBAY_OAUTH_ENVIRONMENT, 32).toLowerCase();
  if (value === "sandbox" || value === "production") return value;

  throw new RequestError(
    "KeepFlip's eBay deletion endpoint must set EBAY_OAUTH_ENVIRONMENT to sandbox or production.",
    500,
  );
}

function credentialsFor(environment) {
  const prefix = environment === "production" ? "EBAY_PRODUCTION" : "EBAY_SANDBOX";
  return {
    clientId: requireEnvironment(`${prefix}_CLIENT_ID`),
    clientSecret: requireEnvironment(`${prefix}_CLIENT_SECRET`),
  };
}

function ebayTokenEndpoint(environment) {
  return environment === "production"
    ? "https://api.ebay.com/identity/v1/oauth2/token"
    : "https://api.sandbox.ebay.com/identity/v1/oauth2/token";
}

function ebayPublicKeyEndpoint(environment, keyId) {
  const host =
    environment === "production" ? "https://api.ebay.com" : "https://api.sandbox.ebay.com";
  return `${host}/commerce/notification/v1/public_key/${encodeURIComponent(keyId)}`;
}

function notificationScopes() {
  const supplied = cleanText(process.env.EBAY_NOTIFICATION_APP_SCOPES, 4_000);
  const scopes = (supplied
    ? supplied.split(/\s+/)
    : ["https://api.ebay.com/oauth/api_scope"]
  ).filter(Boolean);
  const unique = [...new Set(scopes)];

  if (
    unique.length === 0 ||
    unique.some(
      (scope) =>
        !/^https:\/\/api\.ebay\.com\/oauth\/api_scope(?:\/[A-Za-z0-9._-]+)*$/.test(
          scope,
        ),
    )
  ) {
    throw new RequestError(
      "EBAY_NOTIFICATION_APP_SCOPES contains an invalid eBay OAuth scope.",
      500,
    );
  }

  return unique.join(" ");
}

function exactEndpointUrl() {
  const endpoint = requireEnvironment("EBAY_DELETION_ENDPOINT_URL");
  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new RequestError(
      "EBAY_DELETION_ENDPOINT_URL must be the exact public HTTPS endpoint URL.",
      500,
    );
  }

  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new RequestError(
      "EBAY_DELETION_ENDPOINT_URL must be an HTTPS endpoint without credentials, a query, or a fragment.",
      500,
    );
  }

  return endpoint;
}

function verificationToken() {
  const token = requireEnvironment("EBAY_DELETION_VERIFICATION_TOKEN");
  if (!/^[A-Za-z0-9_-]{32,80}$/.test(token)) {
    throw new RequestError(
      "EBAY_DELETION_VERIFICATION_TOKEN must be 32-80 letters, numbers, underscores, or hyphens.",
      500,
    );
  }
  return token;
}

function hmacKey() {
  const keyBase64 = requireEnvironment("EBAY_USER_ID_HMAC_KEY");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(keyBase64)) {
    throw new RequestError(
      "EBAY_USER_ID_HMAC_KEY must be a Base64-encoded 32-byte key.",
      500,
    );
  }

  const key = Buffer.from(keyBase64, "base64");
  if (key.length !== 32) {
    throw new RequestError(
      "EBAY_USER_ID_HMAC_KEY must decode to exactly 32 bytes.",
      500,
    );
  }
  return key;
}

export function hashEbayUserId(userId) {
  return createHmac("sha256", hmacKey())
    .update(`keepflip|ebay-user-id|v1|${userId}`, "utf8")
    .digest("hex");
}

function rawBodyText(req) {
  if (typeof req?.bodyText === "string") return req.bodyText;
  return "";
}

function parseSignatureHeader(headerValue) {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(headerValue)) {
    throw new SignatureError();
  }

  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(headerValue, "base64").toString("utf8"));
  } catch {
    throw new SignatureError();
  }

  const algorithm = cleanText(parsed?.alg, 32).toUpperCase();
  const digest = cleanText(parsed?.digest, 32).toUpperCase();
  const keyId = cleanText(parsed?.kid, 256);
  const signature = cleanText(parsed?.signature, 16_000);

  if (
    algorithm !== "ECDSA" ||
    digest !== "SHA1" ||
    !/^[A-Za-z0-9._-]{1,256}$/.test(keyId) ||
    !/^[A-Za-z0-9+/_-]+={0,2}$/.test(signature)
  ) {
    throw new SignatureError();
  }

  return { keyId, signature };
}

function publicKeyPem(encodedKey) {
  const value = cleanText(encodedKey, 16_000);
  let pem = value;

  if (!value.includes("-----BEGIN PUBLIC KEY-----")) {
    const compact = value.replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
      throw new RequestError(
        "eBay could not provide a usable notification validation key.",
        503,
      );
    }
    const lines = compact.match(/.{1,64}/g);
    pem = `-----BEGIN PUBLIC KEY-----\n${lines?.join("\n") || ""}\n-----END PUBLIC KEY-----`;
  }

  try {
    createPublicKey(pem);
  } catch {
    throw new RequestError(
      "eBay could not provide a usable notification validation key.",
      503,
    );
  }

  return pem;
}

async function appTokenFor({ environment, fetchImpl }) {
  const scopes = notificationScopes();
  const cacheKey = `${environment}|${scopes}`;
  const cached = appTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + APP_TOKEN_CACHE_SAFETY_WINDOW_MS) {
    return cached.accessToken;
  }

  const { clientId, clientSecret } = credentialsFor(environment);
  let response;
  try {
    response = await fetchImpl(ebayTokenEndpoint(environment), {
      body: new URLSearchParams({
        grant_type: "client_credentials",
        scope: scopes,
      }).toString(),
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    });
  } catch {
    throw new RequestError(
      "KeepFlip could not reach eBay to validate the deletion notification.",
      503,
    );
  }

  const rawBody = await response.text();
  if (!response.ok) {
    throw new RequestError(
      "KeepFlip could not validate the deletion notification with eBay.",
      503,
    );
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    throw new RequestError(
      "KeepFlip could not validate the deletion notification with eBay.",
      503,
    );
  }

  const accessToken = cleanText(payload?.access_token, 8_000);
  const expiresIn = Number(payload?.expires_in);
  if (!accessToken || !Number.isFinite(expiresIn) || expiresIn < 60) {
    throw new RequestError(
      "KeepFlip could not validate the deletion notification with eBay.",
      503,
    );
  }

  appTokenCache.set(cacheKey, {
    accessToken,
    expiresAt: Date.now() + Math.min(expiresIn, 7_200) * 1_000,
  });
  return accessToken;
}

async function publicKeyFor({ environment, fetchImpl, keyId }) {
  const cacheKey = `${environment}|${keyId}`;
  const cached = publicKeyCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.pem;

  const applicationToken = await appTokenFor({ environment, fetchImpl });
  let response;
  try {
    response = await fetchImpl(ebayPublicKeyEndpoint(environment, keyId), {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${applicationToken}`,
      },
      method: "GET",
    });
  } catch {
    throw new RequestError(
      "KeepFlip could not reach eBay to validate the deletion notification.",
      503,
    );
  }

  const rawBody = await response.text();
  if (!response.ok) {
    throw new RequestError(
      "KeepFlip could not validate the deletion notification with eBay.",
      503,
    );
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    throw new RequestError(
      "KeepFlip could not validate the deletion notification with eBay.",
      503,
    );
  }

  const pem = publicKeyPem(payload?.key);
  publicKeyCache.set(cacheKey, {
    expiresAt: Date.now() + PUBLIC_KEY_CACHE_TTL_MS,
    pem,
  });
  return pem;
}

async function verifyEbaySignature({ fetchImpl, rawBody, req }) {
  const headerValue = getHeader(req?.headers, "x-ebay-signature");
  const { keyId, signature } = parseSignatureHeader(headerValue);
  const pem = await publicKeyFor({
    environment: ebayEnvironment(),
    fetchImpl,
    keyId,
  });

  try {
    const verifier = createVerify("sha1");
    verifier.update(rawBody, "utf8");
    verifier.end();
    if (!verifier.verify(pem, Buffer.from(signature, "base64"))) {
      throw new SignatureError();
    }
  } catch (caughtError) {
    if (caughtError instanceof RequestError) throw caughtError;
    throw new SignatureError();
  }
}

function appwriteRuntime(req) {
  const endpoint = requireEnvironment("APPWRITE_FUNCTION_API_ENDPOINT").replace(
    /\/+$/,
    "",
  );
  const projectId = requireEnvironment("APPWRITE_FUNCTION_PROJECT_ID");
  const apiKey = getHeader(req?.headers, "x-appwrite-key");

  if (!apiKey) {
    throw new RequestError(
      "KeepFlip could not access its secure eBay connection storage.",
      500,
    );
  }

  return { apiKey, endpoint, projectId };
}

async function appwriteRequest({
  apiKey,
  endpoint,
  fetchImpl,
  method = "GET",
  path,
  projectId,
}) {
  let response;
  try {
    response = await fetchImpl(`${endpoint}${path}`, {
      headers: {
        Accept: "application/json",
        "X-Appwrite-Key": apiKey,
        "X-Appwrite-Project": projectId,
      },
      method,
    });
  } catch {
    throw new RequestError(
      "KeepFlip could not reach its secure eBay connection storage.",
      503,
    );
  }

  const rawBody = await response.text();
  let payload = {};
  if (rawBody) {
    try {
      payload = JSON.parse(rawBody);
    } catch {
      throw new RequestError(
        "KeepFlip's secure eBay connection storage returned an unreadable response.",
        503,
      );
    }
  }

  return { ok: response.ok, payload, status: response.status };
}

async function matchingConnectionRows({ fetchImpl, identityHmac, runtime }) {
  const query = `equal("ebayUserIdHmac",["${identityHmac}"])`;
  const params = new URLSearchParams();
  params.append("queries[]", query);
  params.append("queries[]", "limit(100)");
  const result = await appwriteRequest({
    apiKey: runtime.apiKey,
    endpoint: runtime.endpoint,
    fetchImpl,
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(CONNECTIONS_TABLE_ID)}/rows?${params.toString()}`,
    projectId: runtime.projectId,
  });

  if (!result.ok) {
    throw new RequestError(
      "KeepFlip could not locate the stored eBay connection for deletion.",
      503,
    );
  }

  const rows = Array.isArray(result.payload?.rows) ? result.payload.rows : [];
  return rows
    .map((row) => cleanText(row?.$id, 128))
    .filter((rowId) => Boolean(rowId));
}

async function deleteConnectionRow({ fetchImpl, rowId, runtime }) {
  const result = await appwriteRequest({
    apiKey: runtime.apiKey,
    endpoint: runtime.endpoint,
    fetchImpl,
    method: "DELETE",
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(CONNECTIONS_TABLE_ID)}/rows/${encodeURIComponent(
      rowId,
    )}`,
    projectId: runtime.projectId,
  });

  if (!result.ok && result.status !== 404) {
    throw new RequestError(
      "KeepFlip could not delete the stored eBay connection.",
      503,
    );
  }
}

async function deleteMatchingConnections({ fetchImpl, identityHmac, runtime }) {
  for (let batch = 0; batch < MAX_DELETION_BATCHES; batch += 1) {
    const rowIds = await matchingConnectionRows({
      fetchImpl,
      identityHmac,
      runtime,
    });
    if (rowIds.length === 0) return;

    for (const rowId of rowIds) {
      await deleteConnectionRow({ fetchImpl, rowId, runtime });
    }
  }

  throw new RequestError(
    "KeepFlip could not complete the stored eBay connection deletion.",
    503,
  );
}

async function handleChallenge({ req, res }) {
  const challengeCode = queryValue(req, "challenge_code");
  if (!challengeCode) {
    throw new RequestError("The eBay challenge code is required.", 400);
  }

  const challengeResponse = createHash("sha256")
    .update(challengeCode, "utf8")
    .update(verificationToken(), "utf8")
    .update(exactEndpointUrl(), "utf8")
    .digest("hex");

  return res.json({ challengeResponse }, 200);
}

async function handleDeletion({ fetchImpl, req, res }) {
  const rawBody = rawBodyText(req);
  if (!rawBody || Buffer.byteLength(rawBody, "utf8") > MAX_NOTIFICATION_BYTES) {
    throw new RequestError("The eBay deletion notification body is invalid.", 400);
  }

  await verifyEbaySignature({ fetchImpl, rawBody, req });

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    throw new RequestError("The eBay deletion notification body is invalid.", 400);
  }

  if (payload?.metadata?.topic !== "MARKETPLACE_ACCOUNT_DELETION") {
    throw new RequestError("The eBay notification topic is not supported here.", 400);
  }

  const userId = cleanText(payload?.notification?.data?.userId, 500);
  if (!userId) {
    throw new RequestError("The eBay deletion notification is missing its user identifier.", 400);
  }

  await deleteMatchingConnections({
    fetchImpl,
    identityHmac: hashEbayUserId(userId),
    runtime: appwriteRuntime(req),
  });

  return res.empty();
}

function jsonError(res, caughtError) {
  const statusCode =
    caughtError instanceof RequestError ? caughtError.statusCode : 500;
  const message =
    caughtError instanceof RequestError
      ? caughtError.message
      : "KeepFlip could not process the eBay account-deletion notice.";
  return res.json({ ok: false, error: message }, statusCode);
}

export function createHandler({ fetchImpl = fetch } = {}) {
  return async ({ req, res, log = () => {}, error = () => {} }) => {
    const method = cleanText(req?.method, 16).toUpperCase();
    const path = getRequestPath(req);

    try {
      if (path !== DELETION_PATH) {
        throw new RequestError("Endpoint not found.", 404);
      }

      if (method === "GET") return await handleChallenge({ req, res });
      if (method === "POST") return await handleDeletion({ fetchImpl, req, res });

      throw new RequestError("Use GET for eBay verification or POST for a deletion notice.", 405);
    } catch (caughtError) {
        const statusCode =
          caughtError instanceof RequestError ? caughtError.statusCode : 500;
      
        const errorName =
          caughtError instanceof Error
            ? caughtError.name
            : "UnknownError";
      
        const errorMessage =
          caughtError instanceof Error
            ? caughtError.message
            : "Unknown error";
      
        error(
          `[eBay account deletion] ${method} ${path} failed ` +
          `status=${statusCode} ` +
          `name=${errorName} ` +
          `message=${errorMessage}`
        );
      
        return jsonError(res, caughtError);
      }
  };
}

export default createHandler();
