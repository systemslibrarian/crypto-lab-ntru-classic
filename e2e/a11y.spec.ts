import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NTRU vectors; this
 * gates them on accessibility the same way. Scans the full page with every
 * <details> expanded, in both themes. Animations/opacity transitions are
 * neutralized so a mid-fade frame can't produce a phantom contrast failure.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      transition:none!important;
      animation:none!important;
    }`,
  });
}

async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast): the message field's boundary must reach 3:1
 * against its own fill AND against the page surface behind it. The app body is
 * a gradient, so the "outside" check is run against every color stop of the
 * body's computed background-image (worst case), not just one sample. Axe does
 * not flag border-vs-surface, so this is asserted from computed styles.
 */
async function minControlBorderContrast(page: Page, selector: string): Promise<number> {
  return page.evaluate((sel) => {
    const el = document.querySelector<HTMLElement>(sel);
    if (!el) throw new Error(`no element: ${sel}`);
    type C = { r: number; g: number; b: number; a: number };
    const parse = (s: string): C => {
      const m = s.match(/rgba?\(([^)]+)\)/);
      if (!m) return { r: 0, g: 0, b: 0, a: 0 };
      const p = m[1].split(/[,\s/]+/).map(parseFloat);
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C) => {
      const f = (v: number) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C) => {
      const [hi, lo] = lum(a) > lum(b) ? [lum(a), lum(b)] : [lum(b), lum(a)];
      return (hi + 0.05) / (lo + 0.05);
    };
    // Collect every candidate surface behind the control: ancestor solid
    // background-colors plus every color stop of ancestor gradients.
    const surfaces: C[] = [];
    for (let n = el.parentElement; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      const bg = parse(cs.backgroundColor);
      let opaque = false;
      if (bg.a > 0) {
        surfaces.push(bg);
        if (bg.a >= 1) opaque = true;
      }
      if (cs.backgroundImage && cs.backgroundImage !== 'none') {
        for (const m of cs.backgroundImage.matchAll(/rgba?\([^)]+\)/g)) {
          surfaces.push(parse(m[0]));
        }
        opaque = true;
      }
      if (opaque) break;
    }
    if (surfaces.length === 0) surfaces.push({ r: 255, g: 255, b: 255, a: 1 });
    const cs = getComputedStyle(el);
    const fill = parse(cs.backgroundColor);
    const borderRaw = parse(cs.borderTopColor);
    let worst = Infinity;
    for (const s of surfaces) {
      const base = s.a >= 1 ? s : over(s, { r: 255, g: 255, b: 255, a: 1 });
      const fillC = fill.a > 0 ? over(fill, base) : base;
      const border = over(over(borderRaw, fillC), base);
      worst = Math.min(worst, ratio(border, base), ratio(border, fillC));
    }
    return worst;
  }, selector);
}

test('message field border reaches 3:1 in dark theme (SC 1.4.11)', async ({ page }) => {
  await page.goto('.');
  await page.waitForSelector('#message-input');
  expect(await minControlBorderContrast(page, '#message-input')).toBeGreaterThanOrEqual(3);
});

test('message field border reaches 3:1 in light theme (SC 1.4.11)', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.waitForSelector('#message-input');
  expect(await minControlBorderContrast(page, '#message-input')).toBeGreaterThanOrEqual(3);
});

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await neutralizeMotion(page);
  await expandAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await neutralizeMotion(page);
  await expandAll(page);
  await scan(page);
});

test('lattice attack reports only its checked recovery outcome', async ({ page }) => {
  await page.goto('.');
  await page.locator('#bridge-attack').click();
  const result = page.locator('#bridge-result');
  await expect(result).toContainText(/LLL (recovered|did not recover) the key/);
  if ((await result.textContent())?.includes('recovered the key')) {
    await expect(result).toContainText(/exact match|valid private key/);
  }
});
