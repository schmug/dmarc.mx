import { esc, generateCreature } from "./components.js";
import { page } from "./html.js";

// Shown when the OAuth state check fails on /auth/callback — most often a
// sign-up that outlived the state cookie. A button (not an auto-redirect) so
// a browser that drops cookies can't loop.
export function renderSignInRetryPage(retryUrl: string): string {
  return page({
    title: "Sign-in timed out — dmarcheck",
    path: "/auth/callback",
    noindex: true,
    body: `<main class="breakdown">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} Home</a>
  </div>
  <h1 class="rubric-title">Your sign-in timed out</h1>
  <p>I couldn't finish signing you in. That happens when the sign-up or email-code step takes longer than 30 minutes, or when the sign-in link is opened in a different browser.</p>
  <p>Nothing was lost. Start again and it usually takes a moment.</p>
  <p><a class="monitor-cta" href="${esc(retryUrl)}">Continue signing in</a></p>
</main>`,
  });
}
