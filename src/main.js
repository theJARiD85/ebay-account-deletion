import { Client, Databases, Query } from "node-appwrite";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  validateSignature,
} = require("event-notification-nodejs-sdk/lib/validator");

const DELETION_TOPIC = "MARKETPLACE_ACCOUNT_DELETION";

function required(name) {
  const value = process.env[name];

  if (!value?.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value.trim();
}

function getSdkEnvironment() {
  const environment = required("EBAY_ENVIRONMENT").toLowerCase();

  if (environment === "sandbox") {
    return "SANDBOX";
  }

  if (environment === "production") {
    return "PRODUCTION";
  }

  throw new Error("EBAY_ENVIRONMENT must be sandbox or production.");
}

function getCollectionIds() {
  const collectionIds = required("APPWRITE_EBAY_USER_DATA_COLLECTION_IDS")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean);

  if (!collectionIds.length) {
    throw new Error("No eBay user-data collections were configured.");
  }

  return [...new Set(collectionIds)];
}

function createDatabasesClient(req) {
  const apiKey =
    req.headers["x-appwrite-key"] || process.env.APPWRITE_FUNCTION_API_KEY;

  if (!apiKey) {
    throw new Error("Appwrite function API key is unavailable.");
  }

  const client = new Client()
    .setEndpoint(required("APPWRITE_FUNCTION_API_ENDPOINT"))
    .setProject(required("APPWRITE_FUNCTION_PROJECT_ID"))
    .setKey(apiKey);

  return new Databases(client);
}

async function deleteDocumentsForEbayUser({
  databases,
  databaseId,
  collectionId,
  ebayUserId,
}) {
  while (true) {
    const result = await databases.listDocuments(databaseId, collectionId, [
      Query.equal("ebayUserId", [ebayUserId]),
      Query.limit(100),
    ]);

    if (result.documents.length === 0) {
      return;
    }

    for (const document of result.documents) {
      try {
        await databases.deleteDocument(
          databaseId,
          collectionId,
          document.$id,
        );
      } catch (err) {
        // A duplicate/retried eBay notification may have already removed it.
        if (err?.code !== 404) {
          throw err;
        }
      }
    }
  }
}

export default async ({ req, res, log, error: logError }) => {
  try {
    // eBay validates ownership of the endpoint with this request.
    if (req.method === "GET") {
      const challengeCode = req.query?.challenge_code;

      if (typeof challengeCode !== "string" || !challengeCode) {
        return res.json({ error: "Missing challenge_code." }, 400);
      }

      const challengeResponse = createHash("sha256")
        .update(challengeCode)
        .update(required("EBAY_ACCOUNT_DELETION_VERIFICATION_TOKEN"))
        .update(required("EBAY_ACCOUNT_DELETION_ENDPOINT"))
        .digest("hex");

      return res.json(
        { challengeResponse },
        200,
        { "cache-control": "no-store" },
      );
    }

    if (req.method !== "POST") {
      return res.text("Method not allowed.", 405, {
        allow: "GET, POST",
      });
    }

    const payload = req.bodyJson;

    if (
      !payload ||
      typeof payload !== "object" ||
      payload.metadata?.topic !== DELETION_TOPIC
    ) {
      return res.text("Unexpected notification.", 400);
    }

    const signature = req.headers["x-ebay-signature"];

    if (!signature) {
      return res.text("Missing eBay signature.", 412);
    }

    const signatureIsValid = await validateSignature(payload, signature, {
      clientId: required("EBAY_CLIENT_ID"),
      clientSecret: required("EBAY_CLIENT_SECRET"),
      environment: getSdkEnvironment(),
    });

    if (!signatureIsValid) {
      return res.text("Invalid eBay signature.", 412);
    }

    const ebayUserId = payload.notification?.data?.userId;

    if (typeof ebayUserId !== "string" || !ebayUserId) {
      return res.text("Missing immutable eBay user ID.", 400);
    }

    const databases = createDatabasesClient(req);
    const databaseId = required("APPWRITE_EBAY_DATABASE_ID");

    for (const collectionId of getCollectionIds()) {
      await deleteDocumentsForEbayUser({
        databases,
        databaseId,
        collectionId,
        ebayUserId,
      });
    }

    log(
      `Completed eBay deletion request ${payload.notification?.notificationId ?? "unknown"}.`,
    );

    return res.empty(); // 204 acknowledgement to eBay
  } catch (err) {
    logError(
      `eBay account-deletion webhook failed: ${
        err instanceof Error ? err.message : "Unknown error"
      }`,
    );

    return res.text("Unable to process notification.", 500);
  }
};