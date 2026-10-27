# Android Hunting

#### When to use this file

Use for Kotlin, Java, Compose, or hybrid apps when source-visible Android components, intents, Binder calls, content URIs, WebViews, or device lifecycle create a trust boundary. Select the relevant classes after reconnaissance; the language or Android dependency alone is not a reason to select every class. Use with `DESKTOP-MOBILE-AND-LOCAL-IPC.md` for shared native/IPC paths, `CLIENT-SIDE.md` for web content, and `WEB-PROTOCOL-AND-AUTH.md` for server-side callback handling.

## Core discipline (include in every agent prompt for this domain)

```
- Name a realistic lower-trust caller: another installed app, remote page, document sender, less-privileged account, or stale device state. Do not treat an app calling its own component as an external attack.
- Trace the exact entry component or URI to the final read, write, launch, identity decision, or privileged operation. Identify Android's permission, export, URI-grant, package/signature, or user-consent control on that path.
- Review the final merged release manifest and configuration for the reviewed flavor, targetSdk, minSdk, API level, signing, and installed package when behavior depends on them. Source declarations, debug builds, and assumed platform defaults do not establish release behavior.
- A missing best practice alone is not a finding. Show the attacker-controlled input, reachable sink, crossed principal, and bounded result. Use `needs_validation` for a required manifest, signing, device/API, or runtime fact that cannot be observed.
- Execute target-controlled builds, tests, or emulator code only under the parent skill's OS-enforced sandbox. If unavailable, keep the source-grounded lead as `needs_validation`; never use a live service or another user's device.
```

## Components and URI authority attack classes (subagent_type: `general`)

**Exported component and alias authority**
Enumerate activities, activity aliases, services, receivers, and providers in the final merged release manifest. Trace each reachable explicit or implicit intent/filter, permission and protection level, and handler's sensitive operation. Check aliases and libraries that may expose an otherwise internal activity. An exported entry is a candidate only if a realistic untrusted caller can pass the effective gate and affect another principal or protected resource. Condition conclusions on targetSdk and API behavior where export defaults or intent delivery rules differ.

**ContentProvider and FileProvider scope**
For providers, trace authority, exported status, read/write permissions, path permissions, `grantUriPermissions`, `openFile`/query/update/delete, and data returned. For `FileProvider`, inspect configured roots and whether a concrete URI exposed to another app grants read, write, prefix, or persistable access to more than the intended file. Check final canonical target and symlink handling where relevant. A broad path declaration without a reachable grant and protected file is not enough.

**URI grant propagation**
Trace `data`, `ClipData`, nested intents, chooser/share flows, and `FLAG_GRANT_READ_URI_PERMISSION` / `FLAG_GRANT_WRITE_URI_PERMISSION` through forwarding. Determine which process holds the original grant, which recipient receives it, and whether the forwarded URI is within authorized scope. Do not infer that arbitrary flags grant arbitrary provider data; establish provider grant eligibility and a real untrusted caller.

## Intent, callback, and delegated-action attack classes (subagent_type: `general`)

**Intent redirection and confused launch**
An exported component receives an attacker-controlled nested `Intent`, action, component, package, data, extras, or `ClipData`, then launches, binds, broadcasts, or grants URI access using the app's authority. Trace parsing and sanitization of both outer and nested values, the final resolved target, and grant flags. Require a concrete privileged operation or disclosure, accounting for platform restrictions at the reviewed API/targetSdk.

**PendingIntent capability and reuse**
Map who creates, receives, stores, updates, and sends each `PendingIntent`. Review creator identity, base intent target, filled-in fields, mutability, request code, identity matching, `FLAG_UPDATE_CURRENT`/`FLAG_CANCEL_CURRENT`/`FLAG_ONE_SHOT`, and account or action changes before use. Mutable may be required for inline reply or other platform features; immutability alone does not prevent a recipient from invoking the capability. Report only when a lower-trust holder can select or replay a security-relevant operation outside its intended scope.

**App Link and OAuth callback binding**
Compare claimed and verified link ownership, manifest host/path filters, exact URI parsing, duplicate parameters, current session, OAuth `state`/nonce, PKCE where used, account/provider, and one-time transaction expiry. A custom scheme may be intercepted; a verified App Link still needs transaction binding. Show a callback accepted into the wrong account or operation before claiming takeover. If domain verification, installed-app behavior, or IdP policy is unknown, keep `needs_validation`.

## Binder, WebView, and code-loading attack classes (subagent_type: `general`)

**Binder and service caller identity**
For bound services, AIDL, Messenger, and provider methods, capture the real caller UID during the incoming transaction and verify its package/signature or permission as appropriate. Follow each sensitive method and resource check. `Binder.clearCallingIdentity()` changes the calling identity for downstream work; check that authorization used the original caller before clearing, and that identity is restored. A caller-supplied package name or UID is not proof of caller identity. Account for same-UID apps and APIs that resolve packages from a UID.

**WebView navigation to native bridge**
Trace every origin that can reach `addJavascriptInterface`, message ports/listeners, URL interception, and custom schemes, including redirects, subframes, popups, error pages, and file/content URLs. `addJavascriptInterface` exposes its object to every frame and does not supply the calling frame's origin; `webView.url` is not caller provenance. Check trusted-content isolation and bridge removal before untrusted navigation. For origin-aware message APIs, check the sender origin and allowed target at the message boundary. In all cases, tie a reachable untrusted caller and accepted argument to a protected native sink; enabling JavaScript or a bridge alone is not a finding. Use `CLIENT-SIDE.md` for DOM behavior and this file for native authority.

**Dynamic code and untrusted package input**
If the app loads dex, native libraries, scripts, plugins, or downloaded configuration interpreted as code, trace the exact source, integrity/signature check, storage permissions, and loader path. Show how a lower-trust actor can replace bytes before execution under the app's identity. A dynamic loader using app-owned immutable or verified content is not automatically vulnerable.

## Storage, identity, and transport attack classes (subagent_type: `general`)

**Keystore, backup, and local-data reader**
Identify which app/profile/account can read an encrypted or plaintext file, backup, log, clipboard entry, notification, or exported database; which principal controls the key; and what the data permits. Where the app promises a Keystore-backed boundary, check key alias scope, user-authentication policy, invalidation after enrollment or device changes, and failure fallback against that promise. Review backup rules, device transfer, `allowBackup`, and restore for the reviewed API and release configuration. App-private plaintext or a public client ID alone is not a finding. Require a less-authorized reader or post-revocation capability.

**Account switch and deferred work**
Follow Room/DataStore/preferences, WebView cookies, caches, widgets, notifications, shortcuts, and WorkManager jobs across logout, account switch, restore, and process restart. Check whether a job or callback binds account, tenant, resource, and authorization at execution time, and whether stale work can show or mutate a different account's data. Show the cross-account read/write or stale privileged action; merely retained state is not sufficient.

**Biometric authorization binding**
Trace the operation and account approved by `BiometricPrompt`, the key or `CryptoObject` policy where used, and the action executed after success. Check whether success from a previous prompt/session authorizes a different resource or survives account switch. Biometric presence alone does not prove the user approved every later action; a prompt without transaction binding is a lead until a concrete wrong action is shown.

**TLS and network security by variant**
Read the effective release `networkSecurityConfig`, trust anchors, cleartext policy, certificate validation, hostname checks, custom `TrustManager`/`HostnameVerifier`, and WebView network paths for the reviewed API/targetSdk. `debug-overrides` applies only to debuggable builds; a debug-only CA is not a release trust failure. Missing certificate pinning is not by itself a vulnerability. Require a realistic attacker-controlled network/certificate path reaching protected data or commands despite applicable release controls.

## Universal moves (apply across the above)

- Map package, user/profile, component, URI, and operation for each boundary. Record the lower-trust caller's actual capability, not an assumed arbitrary installed-app privilege.
- Inspect final merged release artifacts when available: manifest, resource overlays, provider paths, network security config, signing and intent-filter metadata. Record flavor, build type, targetSdk, API level, and installation/verification state; unresolved packaging facts remain `needs_validation`.
- Trace one complete source-to-sink path per lead. Include nested intents, `ClipData`, URI flags, alias routes, deferred callbacks, and account transitions only when they are reachable on that path.
- Use dummy accounts and content in bounded local fixtures under the skill sandbox. Stop at the minimum unauthorized read, write, launch, or trust decision. Keep external service, installed-app, and device-policy unknowns explicit.

**Worked boundary trace:** An externally callable share proxy accepts a nested `Intent` with attacker-selected recipient and `ClipData` URI, then forwards it with read-grant flags. If the URI identifies a protected dummy file in the app's grantable provider, ask whether the app, as provider owner, grants the chosen recipient read access. Check the merged release export/permission policy, provider paths, exact URI, forwarded flags, and recipient identity. A bounded isolated fixture showing that the lower-trust recipient reads only that dummy file can establish the result. If release export status or provider grant eligibility is unavailable, retain `needs_validation` with that exact missing fact; do not infer disclosure from the presence of a nested intent alone.

## Validation rules (apply before reporting ANY finding here)

1. State attacker principal and capability, entry channel, effective release/API conditions, accepted value, security check, final sink, affected principal, and observed bounded result.
2. For exported components and URI grants, establish the final manifest/provider policy and the caller's actual ability to invoke or receive the grant. For intent redirection, prove nested value control, final target, and any grant propagation.
3. For `PendingIntent`, distinguish invocation authority from mutability and prove the receiver can alter or replay the sensitive action. For Binder, prove caller identity is captured and checked at the correct point relative to `clearCallingIdentity()`.
4. For callbacks, WebViews, backup, biometric, and network paths, verify the relevant OS, browser, account, configuration, and release controls before assigning impact. Missing pinning, obfuscation, `FLAG_SECURE`, root checks, or an app-private plaintext file are not findings without a crossed boundary.
5. Return `confirmed` only when source and bounded local evidence establish the full result. Return `needs_validation` with the exact merged manifest, signing, API/device, domain verification, runtime, or provider fact and a safe owner-observed/local check. Do not guess severity for unresolved leads.

## Primary sources

- [Android intent and intent-filter behavior](https://developer.android.com/guide/components/intents-filters), [intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection), and [pending intents](https://developer.android.com/privacy-and-security/risks/pending-intent).
- [Manifest components and permissions](https://developer.android.com/guide/topics/manifest/manifest-intro), [content providers](https://developer.android.com/guide/topics/manifest/provider-element), and [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider).
- [Binder caller identity](https://developer.android.com/reference/android/os/Binder), [App Links](https://developer.android.com/training/app-links/verify-android-applinks), and [WebView security](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges).
- [Network security configuration](https://developer.android.com/privacy-and-security/security-config), [backup configuration](https://developer.android.com/guide/topics/data/autobackup), and [BiometricPrompt](https://developer.android.com/reference/androidx/biometric/BiometricPrompt).
- [Android Keystore](https://developer.android.com/privacy-and-security/keystore) and [FileProvider security risks](https://developer.android.com/privacy-and-security/risks/file-providers).
