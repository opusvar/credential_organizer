# Google / Microsoft integrations (D25)

OAuth scopes are modelled as registry **systems** labelled with D16 data/action levels.

| Scope (Google / Microsoft) | D16 label |
|---|---|
| `gmail.readonly` / `Mail.Read` | private-read |
| Gmail send / `Mail.Send` | private-act |
| Calendar read | private-read |
| Calendar write | private-write |
| Drive read / `Files.Read` | private-read |
| Delete (mail, files, events) | act |
| Admin APIs (Workspace / M365 admin) | secret-delegate, owner-only |

## Tokens

- The broker holds the refresh tokens.
- It mints down-scoped, short-lived access tokens per agent, capped by the agent's tier (D16).
- Agents never receive refresh tokens.

## Consent

`cvc integrate google|microsoft` runs a consent wizard that requests only the scopes the registry grants.

## Humans

Provider-native delegation (e.g. Gmail delegation, Outlook delegate access) is recorded in the registry and audited.

## Takeover

Takeover (D15) cannot transfer provider accounts. It revokes cvc's tokens and lists the provider's own mechanisms: Google Inactive Account Manager and Microsoft next-of-kin.

## Sign-in

Google/Microsoft sign-in may optionally be added to Authentik as a password replacement only. On its own it never grants above `low`.

## Pending Nathan

- Personal accounts vs Workspace/M365.
- Which provider first (recommendation: Google first).
