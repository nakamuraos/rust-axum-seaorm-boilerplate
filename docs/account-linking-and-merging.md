# Account linking and merging

Linking connects a provider identity to an existing account. Merging handles an
identity that already created a separate user. Neither operation matches accounts
by email. Different emails are allowed when both accounts are authenticated.

All endpoints below require `Authorization: Bearer <access token>`:

| Method | Endpoint | Purpose |
| ------ | -------- | ------- |
| `POST` | `/api/v1/auth/accounts/proof` | Reauthenticate with `{"password":"..."}` |
| `GET` | `/api/v1/auth/accounts/identities` | List connected provider identities |
| `POST` | `/api/v1/auth/oauth/{provider}/verify` | Reauthenticate a connected provider identity |
| `POST` | `/api/v1/auth/oauth/{provider}/link` | Connect a provider with `{"proof_token":"..."}` |
| `POST` | `/api/v1/auth/accounts/merge/preview` | Check both accounts and show consequences |
| `POST` | `/api/v1/auth/accounts/merge` | Confirm and merge into the authenticated account |

The OAuth endpoints require `oauth2`; Google and generic OIDC also require `oidc`.
Their POST responses contain `authorization_url` and set a signed HttpOnly flow
cookie. Call them from the browser with credentials enabled, then navigate that
browser to the URL. The callback uses the cookie to distinguish login, linking
and verification. OIDC account operations request provider reauthentication.
Provider verification accepts only an identity already owned by that account.

Password and provider verification return `user_id`, `proof_token` and
`expires_in` (300 seconds). A proof is bound to the account and its session
version and cannot be substituted with an access token. With
`success_redirect_url`, provider verification returns
`#account_proof=...&user_id=...`; login and linking return the regular token pair.
Keep proofs in memory, remove callback fragments from browser history, and never
put proofs in query strings, logs or persistent storage.

To connect an unused provider identity, reauthenticate the current account,
then POST its proof to the provider's `/link` endpoint. Successful linking
returns a new session and revokes existing sessions and proofs. If the identity
belongs to another user, the callback returns HTTP 409 and requires a merge.

To merge an accidental OAuth account B into the original account A:

1. While signed in as B, obtain B's proof using its connected provider's `/verify`
   endpoint. Retain that proof while switching accounts.
2. Sign in as A and obtain A's proof using its password or connected provider.
3. With A's access token, POST this body to `/accounts/merge/preview`:

   ```json
   {
     "source_user_id": "B-user-uuid",
     "source_proof": "B-proof-token",
     "target_proof": "A-proof-token"
   }
   ```

4. Show the returned target, source, identities, conflicts and consequences.
   If `can_merge` is true and the user confirms, send the same body with
   `"confirm": true` to `/accounts/merge`.
5. Replace the frontend session with the returned token pair for A.

The transaction locks users in UUID order, rechecks both proofs and transfers
all B's identities to A. A keeps its ID, email, password, profile and role.
B remains with status `Merged`, `merged_into` and `merged_at` for auditing;
its password login is disabled and its email remains reserved. Both accounts'
old access tokens, refresh tokens and proofs are revoked. Preview does not
consume proofs, and final confirmation repeats all checks. Accounts with
different roles cannot merge. Migration rollback refuses to remove account fields
once merge history or session revocations exist.

This boilerplate has no project, organization, subscription or billing tables.
Only authentication identities are transferred. Applications must add their own
conflict checks and transactional data transfers before enabling merge for users
with domain data. Roles and privileges are never combined automatically. Passkey
reauthentication is not implemented.
