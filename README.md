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
