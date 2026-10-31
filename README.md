# Passkey 2FA Authentication Bypass by Replay — Hide My WP Ghost

**Status:** CONFIRMED live, 30 Oct 2026. Full working PoC: ran the real,
unmodified Passkey.php class in a standalone PHP harness (only the handful
of WordPress functions it touches were stubbed - wp_parse_url, home_url,
get_bloginfo, wp_unslash, HMWP_Classes_Tools). Generated a real EC
keypair, built one correctly-signed WebAuthn assertion exactly as a real
authenticator would, called validateAuthentication() twice with the
identical captured assertion - both calls returned true. Researcher:
Yusuf Ozturk (Bardstar).

## Summary
The plugin's passkey (WebAuthn) two-factor login never stores the login
challenge it generates, and never checks the challenge in the client's
signed assertion against anything server-side. Combined with a counter
check that accepts a replayed (unchanged) counter value, a captured valid
passkey assertion can be replayed to bypass this 2FA factor indefinitely.

| | |
|---|---|
| Plugin | Hide My WP Ghost |
| Slug | hide-my-wp |
| Type | CWE-294 (Authentication Bypass by Capture-replay) |
| Files | models/twofactor/Passkey.php, models/Twofactor.php |

## Evidence
`models/twofactor/Passkey.php::passkeyLogin()` generates a random
challenge and returns it to the client, but never writes it to a
transient, session, or user meta:
```php
public function passkeyLogin( $user_id ) {
    $challenge = $this->randomB64u( 32 );
    return [ 'challenge' => $challenge, ... ];
}
```
`models/Twofactor.php::validatePasskeyLogin()` (the AJAX handler that
calls it) only checks a login nonce, never stores the challenge either.

`validateAuthentication()` in Passkey.php verifies the WebAuthn signature
against the stored public key (real, correct `openssl_verify()` use) and
checks origin/rpId hash, but never compares `client['challenge']` (inside
the signed `clientDataJSON`) against any server-stored value. The only
replay guard is a monotonic counter check:
```php
if ( $counter < $prev ) { return false; }
```
This accepts counter == prev, so the exact same previously-used assertion
(same counter) passes again.

## Impact
An attacker who captures one valid passkey assertion (network capture,
malicious extension, shared/compromised device, or a logging bug
elsewhere) can replay it to pass this 2FA factor at any later time,
bypassing the plugin's two-factor authentication entirely.

## Fix
Store the challenge server-side (transient keyed to user + a short TTL)
at `passkeyLogin()` time, and require `client['challenge']` to match it
exactly in `validateAuthentication()`, consuming it on use. Change the
counter check to `$counter <= $prev` reject (strictly increasing only).

## Disclosure plan
SUBMITTED to Patchstack 30 Oct 2026, **REJECTED within 1 minute**: "Out of
scope due to not meeting the bug bounty rules and scope." Matches the
form's own pre-submit warning exactly - "Bypass Vulnerability" is not an
accepted type, and this plugin never showed an mVDP-scope badge (unlike
wp-google-maps, which did). Real, live-PoC-confirmed bug, just not
Patchstack-payable under the standard program with this type. No
resubmission planned via Patchstack; could go to MITRE CNA-LR for a
credit-only CVE like order-approval-woocommerce/drisko-plug if the owner
wants it, but no bounty either way.
