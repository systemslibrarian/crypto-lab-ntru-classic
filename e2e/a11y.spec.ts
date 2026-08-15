import { expect, test } from '@playwright/test';
import {
  NARROW,
  boot,
  driveAllStates,
  expectBaselineNotStale,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * The WCAG 2.1 A/AA gate: two seeded themes × {1280 desktop, 380 phone}.
 *
 * The theme axis is kept even though this lab has only ONE palette, and `boot`
 * asserts that fact rather than pretending otherwise — see the note there. The
 * width axis is new: the gate this replaces had no narrow viewport, so WCAG
 * 1.4.10 was never tested on a page of fixed-width canvases.
 *
 * Every configuration runs the SAME drive, and the drive is the whole point:
 * the previous spec contained no click anywhere, so it scanned the empty
 * arrival page twice and measured none of the nine canvases, neither log, the
 * pipeline, the walkthrough, the lattice, the bridge attack or any of the four
 * equation unlocks.
 */
const CONFIGS = [
  { theme: 'dark' as const, width: 1280, height: 800, label: 'dark / 1280px' },
  { theme: 'dark' as const, ...NARROW, label: 'dark / 380px' },
];

for (const cfg of CONFIGS) {
  test(`WCAG 2.1 A/AA — ${cfg.label}`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize({ width: cfg.width, height: cfg.height });
    await boot(page, cfg.theme);
    await driveAllStates(page, cfg.label);
    expectBaselineNotStale();
    expect(errors, 'no page or console errors during the drive').toEqual([]);
    reportCollected();
  });
}
