# Silent Disco HQ – Staging Apps

This repository includes the staging web UIs (`index.html`, `admin.html`) and the Cloudflare Worker (`worker.js`) that backs the SE2 Events silent disco workflow.

## Deploying the Worker

1. Make sure you have [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) configured for the Cloudflare account that hosts the Worker.
   - If you have Node.js on your computer, open a terminal and run `npm install -g wrangler` to install the CLI.
   - Run `wrangler login` once. A browser window will open so you can allow Wrangler to access your Cloudflare account.
   - After the login succeeds, the terminal prints the account it is connected to. That’s all “step one” requires—Wrangler is now ready to deploy whatever `worker.js` you point it at.
2. Deploy directly from the checked-in source file:
   ```bash
   wrangler deploy worker.js
   ```
   Wrangler will upload the **exact** JavaScript file. There is no build step.
3. Verify the deployment with:
   ```bash
   wrangler tail
   ```
   or by curling `https://api.silentdiscohq.com/health` after the deploy finishes.

### Avoid copy/pasting from `git diff`

If you copy the Worker code from a `git diff` view, the diff headers (e.g. lines that look like `diff --git a/worker.js b/worker.js`) will be pasted into the Worker source. Cloudflare will then throw an error similar to:

```
Uncaught SyntaxError: Unexpected identifier 'git' at worker.js:1:7
```

Because `diff --git ...` becomes the literal first line of the script. To fix this:

- Always copy from the actual `worker.js` file (for example, using your editor’s raw file view).
- Ensure the first line of the Worker begins with the comment `// SE2 Events API worker...` as committed in this repo.

Following the raw-file workflow prevents the syntax error and ensures the Worker parses correctly.

## Admin accounts & event sessions

- Admin access is no longer gated by a single hard-coded key. Use the **Super admin** tools (either inside `admin.html` or at
  `/superadmin/`) to create named accounts for each employee. Each account stores its hashed password + metadata in Workers KV,
  and the Worker mints short-lived auth tokens after login. Super admins can revoke accounts or review per-user activity logs via
  `/super/admins` and `/super/admins/activity`.
- When an employee selects an event and starts a session in the admin console, the Worker issues a session token. That session is
  saved to the browser's `sdhqEventSession` localStorage entry so the check-in form (`index.html`) can lock the event fields and
  send the `sessionId` with every check-in. Multiple events can run simultaneously because every admin session is independent.
- Ending a session (or letting it expire) clears the localStorage entry so the check-in page reverts to the manual event picker.
- Super admins also have access to a per-employee headphone audit feed (powered by `/super/admins/checkins`). From the admin console
  they can load a team member's full headphone history (including returned/lost units) and export it to CSV for investigations or
  nightly reporting.

## Username/password logins + super admin portal

- Staff now sign in to `admin.html` with their own username/password. The overlay lets them create an account, stores the auth token
  locally, and automatically refreshes dashboard data as long as the token remains valid.
- Password changes happen inside the “Admin session” card. Logging out revokes the token and brings back the overlay.
- Super admins live at `/superadmin/` (e.g., `https://app.silentdiscohq.com/superadmin`). The seeded credentials are
  **username:** `Kbell629`, **password:** `3087`. After signing in you can change that password from the account card.
- The super admin portal is the home for creating/removing staff accounts, reviewing per-admin activity, and exporting headphone
  histories. Team members can still self-register from the regular admin UI, but the super portal remains the source of truth.
