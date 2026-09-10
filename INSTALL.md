# Install CyberUzCheck (from a folder / zip)

No Chrome Web Store account needed. Works on Chrome, Edge, Brave, Opera.

1. If you got a `.zip`, unzip it. You should have a folder with `manifest.json` inside.
2. Open `chrome://extensions` (or `edge://extensions`, `brave://extensions`).
3. Turn on **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the unzipped folder.
5. The shield icon appears in the toolbar. Pin it (puzzle-piece menu → 📌).

### Notes

- Chrome will show a "Disable developer mode extensions" prompt on some launches —
  click **Keep** / **Cancel**. It goes away only when the extension is installed
  from the Web Store.
- The extension talks to a backend at
  `https://cyberuzcheck-backend.onrender.com`. To point it at your own backend:
  open the popup → ⚙ → **Backend URL** → Save.
- Nothing you check is stored by the extension. Passwords are SHA-1-prefixed
  before anything leaves your device (k-anonymity).

### Updating

Replace the folder contents with the new version and click the ↻ **reload** icon
on the extension's card in `chrome://extensions`.
