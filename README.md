# KeepFlip eBay Account Deletion Function

This standalone Appwrite Function is KeepFlip's eBay Marketplace Account
Deletion notification endpoint. It is deliberately separate from the OAuth
Function so a public eBay webhook has the smallest possible data-access scope.

It exposes one public route:

```text
GET  /webhooks/ebay/account-deletion   eBay endpoint verification challenge
POST /webhooks/ebay/account-deletion   signed account-deletion notification
```

The `GET` route responds with eBay's required SHA-256 challenge value. The
`POST` route verifies `X-EBAY-SIGNATURE` against eBay's public key before it
looks up or deletes anything. A valid event deletes every matching
`ebay_connections` row and returns `204 No Content`; replayed events also
return `204` safely.

The Function never logs the notification payload, username, immutable eBay
user ID, EIAS token, signature, OAuth code, access token, or refresh token.

## Required connection-table change

Before enabling eBay OAuth or this webhook, add this field to the existing
private `ebay_connections` table:

| Column | Type | Required | Purpose |
| --- | --- | --- | --- |
| `ebayUserIdHmac` | String, 64 | yes | Nonreversible keyed fingerprint of eBay's immutable user ID. |

Create a regular key index on `ebayUserIdHmac` named
`ebay_user_id_hmac_index`. Keep row security enabled and leave table
permissions empty. The Appwrite Functions use their scoped dynamic keys.

The eBay OAuth Function now retrieves eBay's immutable user ID immediately
after consent, derives this HMAC, and stores only the HMAC. Both Functions
must use the same `EBAY_USER_ID_HMAC_KEY` value. Do not store raw eBay IDs,
usernames, EIAS tokens, or the Identity API response.

If you already have connection rows created before this field exists, they
cannot be matched safely until their accounts are disconnected and connected
again. Do not enable production eBay OAuth until every stored connection has
the HMAC field.

## Appwrite setup

1. In Appwrite Console, open **Functions** → **Create Function**.
2. Use these settings:

   | Setting | Value |
   | --- | --- |
   | Name | `KeepFlip eBay Account Deletion` |
   | Function ID | `ebay_account_deletion` |
   | Runtime | `node-22` |
   | Entrypoint | `src/main.js` |
   | Build command | `npm install` |
   | Execute access | `Any` |
   | Timeout | `30` seconds |
   | Dynamic-key scopes | `rows.read`, `rows.write` only |
   | Logging | enabled |

3. Create a manual deployment. Archive the **contents** of this folder so the
   archive root contains `package.json` and `src/main.js`; do not include
   `node_modules`.
4. After the first deployment is active, open **Domains** and copy the
   generated HTTPS `.appwrite.run` domain. Appwrite creates this automatically.
5. Form the exact endpoint URL below, including its path, and use that exact
   same string for the Function variable and the eBay Developer Portal:

   ```text
   https://<your-generated-function-domain>/webhooks/ebay/account-deletion
   ```

6. Add the Function variables below and deploy again.

## Function variables

Add these in Appwrite Console → Function → Settings → Variables. Mark the
Client Secret, verification token, and HMAC key as secrets.

| Variable | Value |
| --- | --- |
| `EBAY_OAUTH_ENVIRONMENT` | `production` for the Production keyset, or `sandbox` while testing |
| `EBAY_PRODUCTION_CLIENT_ID` | Production eBay Client ID |
| `EBAY_PRODUCTION_CLIENT_SECRET` | Production eBay Client Secret |
| `EBAY_SANDBOX_CLIENT_ID` | Sandbox eBay Client ID |
| `EBAY_SANDBOX_CLIENT_SECRET` | Sandbox eBay Client Secret |
| `EBAY_DELETION_ENDPOINT_URL` | Exact URL from the previous section |
| `EBAY_DELETION_VERIFICATION_TOKEN` | A random 32-80 character value using only letters, numbers, `_`, and `-` |
| `EBAY_USER_ID_HMAC_KEY` | The same stable Base64 32-byte key configured on `ebay_oauth` |
| `EBAY_NOTIFICATION_APP_SCOPES` | `https://api.ebay.com/oauth/api_scope` |

Generate a permitted verification token in Windows PowerShell, then copy its
single output into both Appwrite and eBay:

```powershell
$bytes = New-Object byte[] 36
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
```

Generate a stable HMAC key once, then set that exact same value in this
Function and in `ebay_oauth`:

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

Do not place any of these values in an Expo environment variable or source
file.

## eBay Developer Portal setup

1. Open **Application Keys** in the eBay Developer Portal.
2. Select **Notifications** next to the Production App ID that was disabled.
3. Choose **Marketplace Account Deletion**.
4. Add the alert email address.
5. Paste the exact public HTTPS endpoint URL from above.
6. Paste the same verification token used in the Appwrite Function.
7. Save. eBay immediately sends the `GET ?challenge_code=...` verification
   request. A successful save means the challenge response was accepted.
8. Use eBay's test-notification control. A valid test should result in a
   `204` Function response.

Use the Production credentials for a Production keyset. Do not use the
OAuth callback URL for this screen; this Function has its own route.

eBay's requirements and the exact hash ordering are documented at:

- https://developer.ebay.com/develop/guides-v2/marketplace-user-account-deletion
- https://edp.ebay.com/api-docs/sell/notification/overview.html

Appwrite's generated Function domains and HTTP route support are documented
at:

- https://appwrite.io/docs/products/functions/domains
- https://appwrite.io/docs/products/functions/develop

## Local verification

From this folder:

```powershell
npm.cmd run check
npm.cmd test
```
