import AxeBuilder from '@axe-core/playwright';
import type { Result } from 'axe-core';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Four landmark rules axe classifies as "best-practice" rather than tagging
 * `wcag*`, so `withTags(TAGS)` alone does not run them. This page has the shape
 * they catch: a shared `<header role="banner">` above a `<div id="app">` that
 * holds a second `<header class="cl-hero">`, that hero's `<aside>` and a
 * `<main>`.
 */
export const EXTRA_RULES = [
  'landmark-no-duplicate-banner',
  'landmark-unique',
  'landmark-one-main',
  'landmark-complementary-is-top-level',
];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * WHAT THE GATE THIS REPLACES ACTUALLY DID. Two `scan()` calls, each preceded
 * by `neutralizeMotion()` and `expandAll()`, at the project's default viewport:
 *
 *  1. IT NEVER TOUCHED THE LAB. There is no click anywhere in the WCAG tests —
 *     not one. Every result this page produces (both key rings, all four
 *     encrypt/decrypt rings, the four pipeline cells, the lattice canvas, the
 *     keygen log, the LLL readout, the decryption walkthrough, the bridge
 *     attack, every status line and all four equation-unlock states) is drawn
 *     by a button, and none of those buttons was ever pressed. It scanned the
 *     empty arrival page twice and called that an accessibility gate.
 *
 *  2. IT INJECTED `animation:none!important; transition:none!important`
 *     through `addStyleTag`, which BYPASSED `style.css`'s own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     That block does exactly the same two things, so the difference is not the
 *     rendering — it is that the injected version can never catch the block
 *     being edited into something that strands an element invisible, which is
 *     precisely the failure `expectNotBlank` exists for. `.cl-hero` and every
 *     `.card` run `riseIn`, a keyframe from `opacity: 0`.
 *
 *  3. IT FORCE-OPENED THE ONE `<details>` ON THE PAGE. `#decrypt-walkthrough`
 *     is EMPTY until a message has been decrypted — it holds the sentence
 *     "Decrypt a message to populate this walkthrough with live values" — so
 *     what `expandAll()` revealed was a placeholder, in a document no visitor
 *     can load. (Its `removeAttribute('hidden')` loop was a no-op: this page
 *     has no `hidden` attribute anywhere.)
 *
 *  4. IT SCANNED `violations` ONLY, so the entire `incomplete` bucket went
 *     unread, and it had no reflow oracle and no viewport narrower than the
 *     default — so WCAG 1.4.10 was never tested.
 *
 *  5. ITS SC 1.4.11 CHECK TOOK A SELECTOR ARGUMENT AND WAS CALLED TWICE, BOTH
 *     TIMES WITH `'#message-input'`. One element. The check itself was careful
 *     — it walked ancestor gradients and took the worst colour stop — and it
 *     was pointed at the single control whose border carries a comment saying
 *     it was chosen to pass this rule. Fifteen buttons were never measured.
 *
 * AND IT SCANNED THE SAME RENDERING TWICE UNDER TWO NAMES. Two of its four
 * tests clicked `#cl-theme-toggle`, asserted `data-theme="light"` on `<html>`,
 * and scanned "the light theme". THIS LAB HAS NO LIGHT THEME. `style.css`
 * contains no `[data-theme]` selector at all: one palette on `:root`, and
 * `data-theme` is written by the shared bar and read by nothing. `boot()`
 * asserts that rather than papering over it — see the note there — so the day a
 * light theme lands, the gate fails until it is measured for real.
 *
 * HAND-MEASURED, BECAUSE NOTHING AUTOMATED REACHES THEM.
 *
 *  - THE NINE `<canvas>` ELEMENTS. They carry every visual result this lab
 *    produces and are one opaque element to every oracle here; their pixels
 *    come from hard-coded hex in `main.ts`. Against the `#0a0f1a` card behind
 *    them: the ternary +1 blue `#00d4ff` 8.24:1, the −1 pink `#ff00aa` 4.28:1,
 *    the zero grey `#3e414b` 1.45:1, the mod-q gold ramp `#caa000`→`#fff0a8`
 *    6.42:1 to 15.19:1, the cipher ramp `#1f8fff`→`#ff5cc8` 4.60:1 to 6.87:1,
 *    the lattice cyan `#00d4ff` 8.24:1 and magenta `#ff00aa` 4.28:1. Only the
 *    ZERO grey is under 3:1, and it is the absence of a coefficient rather than
 *    a mark — the reading is "how much is lit", and every lit value clears 3:1.
 *  - `.ring-legend`, which is the KEY to those canvases and is
 *    `aria-hidden="true"`, so both oracles skip it. Its text is `--muted`
 *    (#93a6c9) on the card: 7.20:1. Its `.swatch` chips are the canvas colours
 *    above, each with a `rgb(255 255 255 / 12%)` edge. Being `aria-hidden` is
 *    itself reported upward: a screen-reader user gets the canvas's one-line
 *    `aria-label` and no key to what its colours mean.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead. Under the reduced motion this gate
 * asserts, this page's `riseIn` card animations and `.eq-step` transitions are
 * all cancelled outright, so quiescence is immediate — the poll is what proves
 * that rather than assuming it.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page is exactly that shape. `.cl-hero` and every `.card` run
 * `animation: riseIn`, whose keyframes go from `opacity: 0` to `opacity: 1`,
 * and the reduced-motion block sets `animation: none !important` on
 * everything. It is SAFE — neither rule declares `opacity`, so cancelling the
 * animation leaves the initial value of 1 rather than the keyframe's 0 — but
 * that is a property of one absent declaration across five card rules, and the
 * assertion is what turns "safe" into a measurement. It runs in every driven
 * state.
 *
 * `aria-hidden` subtrees are excluded. The one that matters here is
 * `.ring-legend`; see `contrast.ts`'s header for why, and `gate.ts`'s for its
 * hand measurement.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * There IS a mechanism here and it is load-bearing, which is why the OUTCOME is
 * asserted rather than the mechanism: this lab's hero is a real
 * `<header class="cl-hero">` rendered into `<div id="app">` by `main.ts`, so it
 * is NOT scoped inside sectioning content and would imply a second banner on
 * its own. `index.html`'s `dedupeBanner()` demotes it to `role="group"`. That
 * script runs on DOMContentLoaded and the hero is written by a module script
 * AFTER it — so this assertion is also the only thing checking that the two
 * still happen in an order that works.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * THE THEME ARGUMENT IS A CLAIM THIS FUNCTION CHECKS, NOT ONE IT TRUSTS. The
 * gate this replaces clicked the shared bar's toggle, saw `data-theme="light"`
 * appear on `<html>`, and reported that it had scanned a light theme. It had
 * not: `style.css` contains no `[data-theme]` selector anywhere. One palette
 * lives on `:root`, `data-theme` is written by the bar and by the anti-flash
 * script in `index.html`, and NOTHING READS IT. So two of that gate's four
 * tests scanned the identical rendering under a second name.
 *
 * This asserts both halves of the truth: the attribute really is set (which
 * also pins down that the anti-flash script and the toggle agree on the
 * `'theme'` localStorage key — a real failure mode elsewhere in this fleet),
 * AND the painted palette is the same either way. The second assertion is
 * deliberately a ratchet in the other direction: the day this lab grows a light
 * theme, it fails, and the gate has to be told to measure it for real rather
 * than silently continuing to scan dark twice.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The palette is theme-independent — asserted, not assumed. See above.
  const palette = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    return {
      text: root.getPropertyValue('--text').trim(),
      panel: root.getPropertyValue('--panel').trim(),
      accent: root.getPropertyValue('--accent').trim(),
      bg: root.getPropertyValue('--bg').trim(),
    };
  });
  expect(
    palette,
    'this lab has a single palette; if that has changed, the gate must measure the new theme rather than scanning dark twice'
  ).toEqual({ text: '#d9e3fb', panel: '#0f1624', accent: '#00d4ff', bg: '#070b12' });

  await assertSingleBanner(page);

  // The gate this replaces ran `removeAttribute('hidden')` over the whole
  // document. Nothing on this page uses the attribute, so that loop was a no-op
  // — asserted here rather than assumed, because the day something does start
  // using it, the `[hidden] { display: none }` UA rule has specificity (0,1,0)
  // and loses to any author `display` declaration on the same element.
  await expect(page.locator('[hidden]')).toHaveCount(0);

  // Everything below the shared header is rendered into `#app` by `main.ts`, so
  // a navigation that resolves proves nothing.
  await expect(page.locator('#app main .card')).toHaveCount(6);
  await expect(page.locator('#generate-keypair')).toBeEnabled();

  // ── Everything this lab computes ships absent ────────────────────────────
  await expect(page.locator('#keygen-summary')).toHaveText('No keypair generated yet.');
  await expect(page.locator('#keygen-log')).toBeEmpty();
  await expect(page.locator('#decode-output')).toBeEmpty();
  await expect(page.locator('#enc-status')).toHaveText('Ready.');
  await expect(page.locator('#dec-status')).toHaveText('Decryption pending.');
  await expect(page.locator('#bridge-secret')).toHaveText('f and g are hidden until you attack.');

  // Two of the three encrypt/decrypt controls ship DISABLED — the "before the
  // unlock" rendering, which is a real state with its own colours and which the
  // gate this replaces never distinguished from any other.
  await expect(page.locator('#decrypt-message')).toBeDisabled();
  await expect(page.locator('#tamper-ciphertext')).toBeDisabled();

  // All four equations ship locked. This is the state the whole exhibit is
  // built around, and it is only on screen before anything has been pressed.
  await expect(page.locator('.eq-step')).toHaveCount(4);
  await expect(page.locator('.eq-step[data-unlocked="false"]')).toHaveCount(4);
  await expect(page.locator('.eq-badge[data-state="locked"]')).toHaveCount(4);

  // The one <details> on the page ships shut.
  await expect(page.locator('#decrypt-walkthrough')).toHaveCount(1);
  await expect(page.locator('details[open]')).toHaveCount(0);

  // Shipped control defaults.
  await expect(page.locator('#message-input')).toHaveValue('Hello, NTRU 1996!');
  await expect(page.locator('#message-input')).toHaveAttribute('maxlength', '73');
  await expect(page.locator('#message-input')).not.toHaveAttribute('aria-invalid', 'true');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the gate this
 * replaces had no viewport narrower than 1280 — so the criterion was untested
 * on a page that carries two `min-width: 640px` tables, a 640px-min scoreboard,
 * long unbroken hex in three places, and four-column grids in the CBC block
 * comparison. Each wide thing is meant to scroll inside its own
 * `.table-scroll` / `.scoreboard-wrap` / `.byte-lane`; the assertion here is
 * that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every `.table-scroll`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab handles ONE case by hand: `.table-wrap` carries `tabindex="0"`,
 * `role="region"` and an `aria-label`, with a comment naming WCAG 2.1.1. The
 * others were not considered, and they are the ones a drive has to build:
 * `#keygen-log` and `#lll-readout` are `<pre class="log">` with
 * `max-height: 15rem; overflow: auto`, and neither overflows until enough
 * generation attempts or reduction steps have been run; `.scheme-eqs` is
 * `overflow-x: auto` around KaTeX display maths. None of the three has a
 * keyboard route, and none of them existed in any state the gate this replaces
 * ever scanned.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/** Run an assertion that throws, recording rather than throwing when collecting. */
async function soft(label: string, fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(`${label}\n  ${String(e).slice(0, 8000)}`);
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * It ratchets rather than merely logging: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${f.detail}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  if (process.env.NT_BASELINE_CAPTURE) {
    expect(
      'NT_BASELINE_CAPTURE was set',
      'a capture run is not a passing gate — unset NT_BASELINE_CAPTURE'
    ).toBe('');
  }
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Run axe twice and merge, because `withTags` and `withRules` CANNOT BE
 * COMBINED.
 *
 * Both write `options.runOnly`, so chaining them silently keeps only the last
 * one — `@axe-core/playwright`'s own docblock says "Cannot be used with
 * AxeBuilder#withTags" and the implementation is a plain overwrite. A
 * `.withTags(TAGS).withRules([...four landmark rules])` chain therefore runs
 * FOUR BEST-PRACTICE RULES AND NO WCAG RULES AT ALL, and reports a clean
 * `violations` array for a page with any number of WCAG failures on it. Two
 * analyses and a merge is the only shape that runs both sets.
 */
async function analyzeAll(page: Page): Promise<{ violations: Result[]; incomplete: Result[] }> {
  const byTag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const byRule = await new AxeBuilder({ page }).withRules(EXTRA_RULES).analyze();
  return {
    violations: [...byTag.violations, ...byRule.violations],
    incomplete: [...byTag.incomplete, ...byRule.incomplete],
  };
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus the four landmark
 *    best-practice rules in `EXTRA_RULES`, merged from a second axe run.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    `<body>` has no background-color at all and every card is a
 *    `color-mix()` over three stacked gradients, none of which axe resolves.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish, including `aria-prohibited-attr`, where an `aria-label` on a
 *    role-less element hides — a defect that never reaches `violations` at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, which axe has no rule
 *    for; see `nontext.ts`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await analyzeAll(page);

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(`non-text contrast in state: ${label}`, () =>
    expectNoNewNonTextFailures(page, label)
  );
  await soft(`scrollers in state: ${label}`, () => expectScrollersReachable(page, label));
  await soft(`reflow in state: ${label}`, () => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open the one `<details>` by clicking its summary, and assert it opened.
 *
 * Never `d.open = true`. The gate this replaces set `open` from script on a
 * walkthrough that is EMPTY until a message has been decrypted, so what it
 * revealed was the placeholder sentence rather than the algebra.
 */
async function openWalkthrough(page: Page): Promise<void> {
  const d = page.locator('#decrypt-walkthrough');
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS EMPTY. Nine canvases are
 *    blank, both logs are empty, all four equations are locked, two of the
 *    three encrypt/decrypt controls are `disabled` and the walkthrough is shut.
 *    That is the whole of what the gate this replaces ever measured — it
 *    contains no click at all — so everything below this line is new coverage.
 *
 *  - EVERY UNLOCK IS SCANNED BEFORE AND AFTER. The four `.eq-step`s move from
 *    `data-unlocked="false"` (dashed border, "Needs Encrypt" badge) to `"true"`
 *    (solid, `--ok`-tinted border) one at a time as their inputs appear, and
 *    the two disabled buttons become enabled. Both renderings of each are real
 *    states with their own colours.
 *
 *  - THE STATE THAT ONLY EXISTS AFTER ENOUGH WORK. `#keygen-log` and
 *    `#lll-readout` are `overflow: auto` under a 15rem cap: at one generation
 *    attempt and one reduction step they do not overflow and there is nothing
 *    to find. Generation is re-run and Auto-Reduce is pressed so they do, and
 *    whether they can then be scrolled from a keyboard is a WCAG 2.1.1 question
 *    that only exists in a state a drive has to go and build.
 *
 *  - THE FAILING BRANCH AS WELL AS THE PASSING ONE. Tamper produces a
 *    decryption mismatch and a `.status.warn`; an over-long message produces
 *    `aria-invalid="true"` and a red field. Those two are the only routes to
 *    `--warn` and `#ff7f7f` on this page, and neither is reachable without
 *    driving.
 *
 *  - NO FIXED TIMEOUTS. Every step has a DOM completion signal: a status line
 *    changing, a badge switching state, a button returning from `disabled`, a
 *    readout gaining a line.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint — nine blank canvases, four locked equations');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── Exhibit 1: the keypair ──────────────────────────────────────────────
  await page.click('#generate-keypair');
  await expect(page.locator('#keygen-summary')).toContainText('Keypair ready');
  await expect(page.locator('#keygen-log')).not.toBeEmpty();
  await expect(page.locator('.eq-step[data-eq="h"]')).toHaveAttribute('data-unlocked', 'true');
  await expect(page.locator('.eq-step[data-unlocked="false"]')).toHaveCount(3);
  await scanAt('keypair generated — the h equation unlocked, three still locked');

  // Key generation retries until f is invertible, so the log length varies per
  // run. Press until it actually overflows its 15rem cap, which is the only
  // state in which the 2.1.1 question about that scroller exists at all.
  const log = page.locator('#keygen-log');
  const overflows = () =>
    log.evaluate((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1);
  for (let i = 0; i < 12 && !(await overflows()); i++) {
    await page.click('#generate-keypair');
    await expect(page.locator('#keygen-summary')).toContainText('Keypair ready');
  }
  expect(await overflows(), 'the keygen log must be made to overflow its box').toBe(true);
  await scanAt('keygen log overflowing its box — a scrolling region');

  // ── Exhibit 2: encrypt, decrypt, tamper ─────────────────────────────────
  await expect(page.locator('#decrypt-message')).toBeDisabled();
  await page.click('#encrypt-message');
  await expect(page.locator('#enc-status')).toContainText('ternary coefficients');
  await expect(page.locator('#dec-status')).toContainText('Ciphertext ready');
  await expect(page.locator('#decrypt-message')).toBeEnabled();
  await expect(page.locator('#tamper-ciphertext')).toBeEnabled();
  await expect(page.locator('.eq-step[data-eq="e"]')).toHaveAttribute('data-unlocked', 'true');
  await scanAt('encrypted — three rings drawn, the e equation unlocked');

  await page.click('#decrypt-message');
  await expect(page.locator('#dec-status')).toContainText('Valid decryption');
  await expect(page.locator('#decode-output')).toContainText('Recovered text');
  await expect(page.locator('.eq-step[data-unlocked="false"]')).toHaveCount(0);
  await expect(page.locator('#pipe-margin')).not.toBeEmpty();
  await scanAt('decrypted — the pipeline drawn and all four equations unlocked');

  await openWalkthrough(page);
  await expect(page.locator('#walkthrough-body')).not.toContainText('Decrypt a message to populate');
  await scanAt('the decryption walkthrough open, with live values in it');

  // The failing branch. Tamper corrupts two coefficients, so decryption is
  // supposed to MISMATCH — the only route to `.status.warn` in this exhibit.
  await page.click('#tamper-ciphertext');
  await expect(page.locator('#dec-status')).toContainText('coefficients now differ');
  await expect(page.locator('#dec-status')).toHaveClass(/warn/);
  // Tampering also swaps the status into `role="alert" aria-live="assertive"`,
  // which is a different accessibility object from the polite one it replaces.
  await expect(page.locator('#dec-status')).toHaveAttribute('role', 'alert');
  await scanAt('ciphertext tampered — the decryption-mismatch warning');

  // The other failing branch: an over-length message. `maxlength` counts UTF-16
  // code units and the validation counts UTF-8 BYTES, so 40 two-byte characters
  // is 80 bytes inside a 73-character cap — the only way to reach the invalid
  // state through the control rather than around it.
  await page.fill('#message-input', 'é'.repeat(40));
  await expect(page.locator('#message-input')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#message-meta')).not.toBeEmpty();
  await scanAt('message too long — the invalid field and its live byte count');

  await page.click('#encrypt-message');
  await expect(page.locator('#enc-status')).toContainText('too long');
  await expect(page.locator('#enc-status')).toHaveClass(/warn/);
  await scanAt('encrypt refused on an over-long message');

  await page.fill('#message-input', 'a');
  await expect(page.locator('#message-input')).not.toHaveAttribute('aria-invalid', 'true');
  await page.click('#encrypt-message');
  await page.click('#decrypt-message');
  await expect(page.locator('#dec-status')).toContainText('Valid decryption');
  await scanAt('a one-byte message encrypted and recovered');

  // ── Exhibit 3A: the 2D lattice ──────────────────────────────────────────
  await page.click('#lll-step');
  await expect(page.locator('#lll-readout')).not.toBeEmpty();
  await scanAt('one Gauss-Lagrange reduction step applied');

  await page.click('#lll-auto');
  await expect(page.locator('#lll-state')).not.toBeEmpty();
  const readout = page.locator('#lll-readout');
  await expect(readout).toContainText(/b1|b₁/);
  await scanAt('basis auto-reduced to its shortest vectors');

  await page.click('#lll-new');
  await expect(page.locator('#lll-state')).not.toBeEmpty();
  await scanAt('a new random basis on the same lattice');

  // ── Exhibit 3B: the bridge to a real NTRU key ───────────────────────────
  await expect(page.locator('#bridge-secret')).toHaveText('f and g are hidden until you attack.');
  await page.click('#bridge-attack');
  await expect(page.locator('#bridge-result')).toContainText(/LLL (recovered|did not recover) the key/);
  await expect(page.locator('#bridge-secret')).not.toHaveText('f and g are hidden until you attack.');
  await scanAt('LLL run on the real 10-dimensional NTRU lattice');

  await page.click('#bridge-new');
  await expect(page.locator('#bridge-state')).toContainText(/fresh small NTRU key/i);
  await expect(page.locator('#bridge-secret')).toHaveText('f and g are hidden until you attack.');
  await scanAt('a fresh small key loaded — the secret hidden again');

  // ── The last state: everything on the page populated at once ────────────
  await page.click('#bridge-attack');
  await expect(page.locator('#bridge-result')).toContainText(/LLL (recovered|did not recover) the key/);
  await scanAt('the finished page — every exhibit populated');
}
