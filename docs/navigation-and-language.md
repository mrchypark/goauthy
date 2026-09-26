# Navigation and language contract

GoAuthy has three navigation contexts: public entry, personal account, and administration. Authentication and consent are transactions with their own destinations; they are not interchangeable pages of the administration console.

## Paths

| Scenario | Forward path | Back / exit |
|---|---|---|
| Public entry | Root → sign-in → Root → role-based workspace | GoAuthy logo → role-based workspace |
| Administrator | Account → Dashboard → management list → new/detail/edit | Explicit list/cancel link; permanent sidebar; My account → dashboard link |
| Member | Root → sign-in → Root → role-based workspace | Home; no administrator link without administrator authority |
| Signed out / expired session | Account → account sign-in; denied admin page → sign-in/account | Home and sign-out-to-switch-account links; original HTTP denial retained |
| Account sections | Overview / Security / Passkeys / Connections / Devices | Anchors only for available sections |
| Logout | Account/admin → confirmation → Home or validated RP destination | Cancel → Account without revoking the session |
| Registration / recovery | Login opens separate tab → form → neutral email notice | Return to original app/tab; Home or standalone Account sign-in fallback |
| Reset email | Delivered HTML link → explicit verification → new-password form | No authentication is granted by recovery; return to original app and sign in |
| Device | Login → code entry (login when needed) → request review → explicit approve/deny | Different code; exit to Account without implicit approval or denial |
| Connection handoff | Requesting app → owner login → consent → completion | Account exit while pending; completed request returns only via validated ReturnURI |
| Required profile | Existing login transaction → required fields → original continuation | Exit to Account; does not cancel an OAuth transaction |
| External connection callback | Provider callback → result → Account connections | Only existing validated callback/return behavior |

Home/Exit is navigation, not cancellation. It does not sign out, grant consent, or report `access_denied`. Existing explicit Device/Handoff denial remains a server mutation. OIDC cancellation is not invented by navigating away; a dedicated interaction-bound cancellation endpoint remains separate work if absent.

## Language

Supported UI languages: English (`en`) and 한국어 (`ko`). Selection uses a host-only, issuer-path scoped `goauthy_ui_locale` cookie, one year, SameSite=Lax, Secure under HTTPS. Only these two exact values override the bounded weighted Accept-Language resolver. Unsupported input falls back to header resolution and ultimately English. This preference never changes account/email language (`locale`), permissions, or authentication policy.

HTML receives the same resolved language as JavaScript through `html.lang`; responses are no-store and vary on Cookie/Accept-Language. Translations apply only to explicit application-owned catalog keys, never to user names, provider names, identifiers, scopes, or arbitrary API data. Raw backend diagnostic details may remain English.

- Home, Account, Admin and public request forms: selector reloads only explicitly classified read-only presentation pages; edited forms require confirmation before changing the cookie.
- Login: selector translates in place without replacing interaction/CSRF, clearing inputs, changing expiry or reloading authentication.
- OTP/profile continuation, one-time reset and consent/callback results: consume the selected language, but do not offer unsafe reload-based selection.
- Pending mutations disable the selector. No credentials are stored to preserve forms across language changes.

## Independent review

Pro design review (not implementation approval): https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46/c/6ab7bbc9-28e0-83e8-9ac0-bbe1e30b6c4d

Conditional GO. Accepted: explicit reload capability rather than assuming GET is safe; exactly one server-owned login destination; distinction between navigation, denial and logout; shared-cookie awareness across tabs; prefixed-issuer destinations; denial pages must retain navigation and HTTP status. Browser verification and handler/security tests are separate evidence.

## Verification ledger

2026-09-26, disposable localhost preview, existing bootstrap administrator:

- Directly clicked Home → account login → Account → Dashboard → Account, account Security anchor → Dashboard, and logout cancel → Account / confirm → Home.
- Opened all 14 administration sections. Opened and cancelled user, client, role, group, API-key, scope, attribute, collection and provider forms; opened the existing user's edit screen and returned to its list.
- Switched Korean/English; the edited-account language dialog cancelled without navigation and confirmed with a language reload. The unsupported self-delete section stayed hidden.
- Opened device code entry, submitted an invalid code, and used its account exit. Opened recovery, submitted a nonexistent fixture email, and returned from the neutral result. Opened registration and expanded optional fields without creating an account.
- Logged out and opened the admin URL: access guidance retained working sign-in and Home links.
- Tested CSS viewport widths 1422, 911 and 433 (the browser's existing 90% zoom affects the requested viewport). Account and sampled administration forms did not widen the document. This is browser viewport testing, not physical-device testing.
- All ten affected Go packages passed. After the final module localization integration, all seventeen JavaScript suites passed. Focused Go navigation/language tests passed again for the subsequently edited account, administration and device pages. `git diff --check` passed.
- Final responsive check: desktop/tablet show navigation with no menu toggle; mobile shows the toggle, hides the menu initially, and opens/closes it with the expected `aria-expanded` state. All three dashboard widths had no document overflow. The mobile API-key form now has a working top-of-form list link.
- Live testing caught a wrong-password 503 regression: the new response wrapper did not expose `Unwrap`, preventing `http.ResponseController.SetWriteDeadline` during the punitive delay. Added forwarding and a regression test. Rebuilt and directly verified wrong password → 401 with navigation → correct password → Account. Also rechecked the translated invalid-device-code alert.

Responsive classes use desktop >1000px, tablet 541–1000px and mobile ≤540px. The administration navigation uses a side rail, horizontal navigation and a mobile disclosure respectively. Account controls wrap on tablet; mobile section links scroll in their own strip.

Not claimed as live-tested: credential changes, hardware passkeys, upstream IdP/FedCM, MFA/profile-required transitions, actual access grants/revocation, CAPTCHA, non-admin account and prefixed issuer deployment. Relevant handler and behavior tests cover several of these boundaries, but are separate evidence. Existing denied admin navigation was tested signed out, not using a real non-admin account.

Root `/` is a no-store redirect: anonymous → `/account/login`, authenticated administrator → `/auth/v1/admin/dashboard`, other active account → `/account`. Standalone account login returns to this fixed root; OAuth/device/handoff destinations are unchanged. Root query parameters never select a destination. The former public landing page has been removed.
