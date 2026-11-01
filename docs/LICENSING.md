# Licensing — what to track if cvc goes paid

> Status: **tracking in place, project license DECISION PENDING (owner).**
> This repo has no LICENSE file on purpose. Until one is added, cvc is "all rights
> reserved" by default. Not legal advice; get a lawyer to review before selling.

## 1. Dependency licenses (automated)

- `scripts/license_inventory.py` walks the full installed closure of runtime deps,
  optional extras (`[estate]`) and `[dev]` via `importlib.metadata` (offline) and
  writes `THIRD_PARTY_LICENSES.md` + `licenses.json`.
- `tests/test_licenses.py` (also run by `.github/workflows/licenses.yml`) fails if:
  - any **runtime** dependency is `deny` (incl. unknown/missing license metadata), or
  - the committed inventory is stale (direct deps' name/license/scope changed), or the
    markdown and JSON disagree.
- After changing dependencies: `python scripts/license_inventory.py` and commit both files.

### Policy

| Verdict | Licenses | Meaning for a paid, closed or dual-licensed cvc |
|---|---|---|
| allow | MIT, BSD-*, Apache-2.0, ISC, PSF, Unlicense/CC0, MPL-2.0, EDL-1.0 | Fine. Keep notices (ship THIRD_PARTY_LICENSES.md; Apache-2.0 NOTICE files). MPL-2.0 is file-level: fine unmodified; changes to MPL files must be published. |
| review | LGPL-*, EPL-* | Usually OK as an unmodified, dynamically-imported Python dep, but needs a human look (relinking/replaceability, modification obligations). |
| deny | GPL-*, AGPL-*, SSPL, unknown | Must not be linked/imported into the product. Run it as a separate service, replace it, or pick a GPL-compatible project license. |

Dual-licensed expressions take the best option (`EPL-2.0 OR BSD-3-Clause` -> allow, we
elect BSD); `AND` takes the worst. Optional/dev deps are reported but don't fail CI —
dev tools are not distributed; extras are, so promote them to the same bar before shipping.

**Current state (2026-11-01):** 35 packages, all `allow`. Notables: `paho-mqtt` is
EPL-2.0 **OR** BSD-3-Clause — we rely on the BSD election; `certifi`/`pathspec` are
MPL-2.0 (unmodified, OK); `segno` declares only a "BSD License" classifier.

## 2. Vaultwarden and the AGPL

Vaultwarden is **AGPL-3.0**. cvc never imports it; it talks to it over HTTP. That is
the key line:

- **Service, not linking.** A separate program communicating over a network API is
  generally not a "derivative work". cvc's own license is unaffected by Vaultwarden's
  as long as cvc stays a client and doesn't copy Vaultwarden code (or Bitwarden client
  code, which is GPL-3.0) into its tree.
- **Distributing Vaultwarden with the product** (e.g. deploygen emitting manifests that
  pull the upstream image, or shipping an appliance image) is "mere aggregation" —
  allowed, but you must pass on the AGPL terms and offer corresponding source for the
  exact Vaultwarden version you ship. Prefer pulling the unmodified upstream image.
- **Network clause (AGPL s13).** If you **modify** Vaultwarden and let users interact
  with it over a network, you must offer those users the modified source. Unmodified =
  just point to upstream. Rule: don't patch Vaultwarden; contribute upstream or wrap it.
- **Offering hosted Vaultwarden** (a managed cvc SaaS where you run Vaultwarden for
  customers) is allowed under AGPL, same s13 duty if modified. Also note Bitwarden's
  server-side licensing is separate and the official Bitwarden clients customers use are
  GPL/Bitwarden-licensed — fine to use, not to rebrand.
- Track: Vaultwarden version per release, whether patched (should be "no"), where the
  source offer lives.

Other deployed components (Authentik MIT core + proprietary `enterprise/`, step-ca,
Traefik, k3s, Home Assistant, Mosquitto, Tailscale) are listed in the services section
of `THIRD_PARTY_LICENSES.md`. Watch: **Authentik enterprise features** need a paid
Authentik license if used; **Tailscale's control plane** is a proprietary SaaS with its
own ToS (commercial use / seat limits) — a product depending on it inherits that; Headscale
(BSD-3) is the self-hosted alternative.

## 3. Trademarks

Licenses cover code, not names. In product name, domain, logo and marketing:

- **Bitwarden** is a registered trademark of Bitwarden Inc. Don't imply affiliation;
  "compatible with Bitwarden clients" in plain text is the safest form.
- **Vaultwarden** asks not to be confused with Bitwarden; same nominative-use rules —
  "uses Vaultwarden", never a Vaultwarden logo or a name like "cvc Vaultwarden Pro".
- **YubiKey / Yubico**, **Tailscale**, **Home Assistant** are trademarks — describe
  compatibility ("works with YubiKey"), follow each brand's guidelines, no logos without
  permission.
- Do a basic trademark search on the product name itself before launch.

## 4. Customer licenses / entitlements (future)

If cvc sells tiers, keep a `licenses` registry alongside the access registry (same
YAML + audit pattern as `cvc.access`). Proposed record:

| Field | Notes |
|---|---|
| `customer` | id + contact |
| `tier` | e.g. personal / family / estate / business |
| `seats` | max users |
| `devices` | enrolled device ids, max count |
| `issued`, `expiry` | dates; grace period policy |
| `key_id` | signed license key (Ed25519; verify offline, no phone-home required) |
| `status` | active / expired / revoked, with audit trail |

Enforcement should degrade gracefully (read-only / no new devices) — never lock a user
out of their own credentials, especially the estate/takeover flows.

## 5. Project license options — DECISION PENDING (owner)

| Option | What it means | Pros | Cons |
|---|---|---|---|
| **Proprietary** | Closed source, EULA | Max control; simplest to sell | No community trust for a *credential* tool; no outside audit; you carry all security review |
| **AGPL-3.0 + commercial dual license** | Public under AGPL; sell exceptions | Same license family as Vaultwarden; competitors who host it must open changes; trust via open source | Need a CLA to relicense contributions; some companies ban AGPL; buyers of "exception" are few for a consumer tool |
| **BSL / FSL (source-available, converts)** | Source visible; non-compete use restricted; converts to Apache/MIT after 2 yrs (FSL) or up to 4 (BSL) | Auditability + protection from clones hosting it; FSL is simple and standardized | Not OSI "open source"; some community pushback; must define "competing use" well |
| **Apache-2.0 open core + paid add-ons** | Core open, premium features (estate kit, business tiers, hosted) closed | Widest adoption, patent grant, easy contributions | Anyone can host the core; line between core and paid is a constant product decision |

**Recommendation (pending): FSL-1.1-Apache-2.0** (Functional Source License, converts
to Apache-2.0 after two years). Reasoning: a credential/estate tool sells on trust, so
customers and reviewers need to read the source; FSL allows that and self-hosting for
personal use while stopping someone from reselling a hosted clone during the window;
old versions become Apache-2.0 automatically, which answers "what if the company
disappears?" — important for an estate-planning product. It's compatible with all
current deps (all permissive) and with running AGPL Vaultwarden as a separate service.
Runner-up: AGPL-3.0 + commercial if community contributions matter more than revenue
protection.

Before adding any LICENSE: decide, add a CLA/DCO policy if dual-licensing, add SPDX
headers, and re-run the inventory.
