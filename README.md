# SecureVault PWA — iPhone-first starter

A dark, installable Progressive Web App. It is designed to be hosted as a static HTTPS site and added to an iPhone Home Screen from Safari.

## Included
- iPhone-oriented dark interface
- Add, edit, search, view and delete saved credentials
- Email and LMS user ID/password fields
- Password generator with Refresh, length and character controls
- Offline app shell
- Local encrypted vault using AES-GCM and Web Crypto
- Face ID / device passcode authentication through WebAuthn platform passkeys
- WebAuthn PRF extension is required to derive the encryption key; setup fails closed if unavailable

## Free hosting using GitHub Pages
1. Create or sign in to a GitHub account.
2. Create a new **public** repository named `securevault-pwa`.
3. Upload every file in this folder to the repository root (including `icon-192.png` and `icon-512.png`).
4. In the repository, open **Settings → Pages**.
5. Under **Build and deployment**, choose **Deploy from a branch**, select `main` and `/ (root)`, then Save.
6. Wait for GitHub Pages to publish the site. Open the HTTPS Pages URL in Safari on your iPhone.
7. In Safari, tap **Share → Add to Home Screen → Add**.

GitHub Pages is free for public repositories. The source files in a public repository are visible to anyone, but vault contents and keys are not in the repository; they remain in the browser's local IndexedDB. Never put credentials in source files or repository settings.

## First launch
- Open the hosted HTTPS URL in Safari on the iPhone.
- Tap **Set up with Face ID**.
- Safari/iOS should ask to create and use a platform passkey. Face ID or device passcode verifies the user.
- The WebAuthn PRF extension must be supported and enabled by the browser/authenticator. If it is not, setup will stop and no plaintext fallback is used.
- Use the same iPhone, browser profile and exact website origin for future unlocks.

## Critical limitations and security notes
- This is a prototype, not an audited password manager. Do not store important/production credentials until you have tested it and reviewed the security.
- Face ID support in web apps is not the same as native iOS Keychain access. This app uses WebAuthn platform passkeys and the WebAuthn PRF extension to derive a local AES-GCM key. PRF availability varies by iOS/Safari version and authenticator. It deliberately refuses setup when PRF is unavailable.
- No server, cloud sync, password recovery, or backup is included. Clearing Safari website data, removing the site data, changing origin, or losing the device/passkey can make the vault unrecoverable. Export/backup should be designed and security-reviewed before storing real credentials.
- GitHub Pages hosting is public static hosting. The app source is public, not your saved vault. Do not add secrets to the repository.
- The app locks when the page becomes hidden. Browser lifecycle behavior can vary; this is not equivalent to a native app's secure enclave.
- Generated passwords are not automatically applied to Gmail, LMS, or other services. Change the password on the service's official website, then edit the saved record in SecureVault.
- Clipboard contents may remain available to other apps temporarily.
- Do not share screenshots or screen recordings containing passwords.
