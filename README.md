# EveryFinder (desktop)

An OSINT toolkit launcher with a built-in terminal.

## Run it
1. Install Node.js (LTS) from nodejs.org.
2. In this folder: `npm install`
3. Start the app: `npm start`

## Build a portable .exe (Windows)
`npm run dist` creates a single portable file in the `dist` folder: `EveryFinder-1.0.0-portable.exe`. It runs without installing; copy it anywhere and double-click it.

If the build fails with a symbolic link or privilege error, turn on Developer Mode in Windows settings or run PowerShell as administrator, then try again. If PowerShell blocks npm, run `npm.cmd run dist` instead.

## The Terminal tab
- It runs one persistent shell on your computer (PowerShell on Windows, your default shell elsewhere), so `cd` and virtual environments carry over between commands.
- It is a pipe-based terminal, not a full one: programs that need an interactive screen or password prompts will not work. Long-running tools such as SpiderFoot's web server work fine.
- Toolkit entries have Run in terminal buttons. Run installs commands after a confirmation; Run fills the command into the input so you press Enter.
- "Stop all" kills the shell and every program it started, then restarts it.
- "Mark found accounts from output" reads the terminal text and ticks matching platforms for the current Username target.

Only run commands you trust. The terminal has the same access to your computer as you do.

Use OSINT tools only on your own details, public information for lawful purposes, or targets you are authorized to assess.

## API tab
Paste free API keys for Shodan, VirusTotal, URLScan (optional) and AbuseIPDB, then run a lookup on the current target and read the result inside the app. crt.sh needs no key. Keys are encrypted with your operating system's secure storage and kept in the app's data folder. The page never sees a saved key again. If secure storage is unavailable, keys cannot be saved.

## Utilities tab
File hashing (SHA-256 and SHA-1), JPEG metadata reader, base64/URL/hex decoders, a timestamp converter and an IPv4 range calculator. Everything runs on your device.

## Run and mark found
With a Username target, the Toolkit's Run and mark found button runs Sherlock, Maigret, Blackbird or Social Analyzer in the terminal and ticks the matching platforms when it finishes.

## Framework tab
Shows the live OSINT Framework website (osintframework.com) inside the app, so it is always current. The embedded page is limited to that site: links to tools open in your default browser, and the page has no access to your computer or to EveryFinder's data.

## Automatic screen updates
On startup (after a few seconds) the app checks this repository (https://github.com/Torchx7/EveryFinder--) for a newer `renderer/index.html`. If `version.json` at the top of the repo has a higher version number, the app downloads `renderer/index.html`, checks its SHA-256 hash against the one in `version.json`, saves it in the app's data folder and offers to reload. If you are offline or anything fails, the app keeps using the copy it already has.

To publish an update:
1. Replace `renderer/index.html` in the repo with the new file.
2. Replace `version.json` with the matching one (a higher version number). If you edited the file yourself, create it with `node make-version.js renderer/index.html <number>`.
3. Commit both. The app picks them up the next time it starts.

Changes to `main.js`, `preload.js` or `package.json` (terminal, API keys, window behaviour) are not covered. Those need a rebuild with `npm run dist`.

Anyone who can edit this repository can change what the app runs, and the terminal runs commands on your computer. Use two-factor authentication on the GitHub account and keep the repo yours alone.
