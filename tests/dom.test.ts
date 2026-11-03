// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * End-to-end smoke test of the UI module in a headless DOM: it proves main.ts
 * boots without runtime errors, KaTeX typesets the scheme equations, and the
 * full generate → encrypt → decrypt flow works through the real click handlers.
 */
beforeAll(async () => {
  // Minimal 2D-context stub: every method is a no-op, every property assignable.
  const ctx = new Proxy(
    {},
    {
      get: () => () => undefined,
      set: () => true,
    },
  );
  // @ts-expect-error test stub of the canvas 2D context
  HTMLCanvasElement.prototype.getContext = () => ctx;

  if (typeof window.matchMedia !== 'function') {
    // @ts-expect-error test stub
    window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  }

  document.body.innerHTML = '<div id="app"></div>';
  await import('../src/main.ts');
});

describe('UI boot', () => {
  it('renders all five exhibits', () => {
    for (let i = 1; i <= 5; i += 1) {
      expect(document.querySelector(`#exhibit${i}`)).not.toBeNull();
    }
  });

  it('typesets the scheme equations with KaTeX', () => {
    const eqs = document.querySelectorAll('.scheme-eqs .katex');
    expect(eqs.length).toBeGreaterThanOrEqual(4);
  });

  it('initializes the lattice reduction at step 0', () => {
    const readout = document.querySelector('#lll-readout');
    expect(readout?.textContent).toContain('Step 0');
  });

  it('states the hybrid parameter boundary and links both primary sources', () => {
    const exhibit = document.querySelector('#exhibit3');
    expect(exhibit?.textContent).toContain('three demo-selected weights is an educational hybrid');
    expect(
      exhibit?.querySelector('a[href="https://www.ntru.org/f/hps98.pdf"]'),
    ).not.toBeNull();
    expect(
      exhibit?.querySelector('a[href="https://www.ntru.org/f/NTRUEncrypt.zip"]'),
    ).not.toBeNull();
    expect(document.querySelector('#exhibit4')?.textContent).not.toContain('2^-80');
  });
});

describe('generate → encrypt → decrypt flow', () => {
  it('drives the full happy path through the UI handlers', () => {
    const click = (id: string) => (document.querySelector(id) as HTMLButtonElement).click();

    click('#generate-keypair');
    expect(document.querySelector('#keygen-summary')?.textContent).toMatch(/Keypair ready/);

    const input = document.querySelector('#message-input') as HTMLInputElement;
    input.value = 'lattice';

    click('#encrypt-message');
    expect(document.querySelector('#enc-status')?.textContent).toMatch(/Encoded/);
    expect((document.querySelector('#decrypt-message') as HTMLButtonElement).disabled).toBe(false);

    click('#decrypt-message');
    expect(document.querySelector('#dec-status')?.textContent).toMatch(/Valid decryption/);
    expect(document.querySelector('#decode-output')?.textContent).toContain('lattice');
  });

  it('populates the decryption walkthrough with a confirmed identity', () => {
    const body = document.querySelector('#walkthrough-body');
    expect(body?.querySelector('.katex')).not.toBeNull();
    expect(body?.textContent).toMatch(/holds exactly/);
  });

  it('retracts the honest verdict after corruption and disclaims authentication', () => {
    const click = (id: string) => (document.querySelector(id) as HTMLButtonElement).click();
    click('#tamper-ciphertext');

    const badges = Array.from(document.querySelectorAll('.eq-badge'), (badge) => badge.textContent);
    expect(badges).toEqual([
      'h is on screen ✓',
      'e is on screen ✓',
      'identity broken ✗',
      "m' mismatch ✗",
    ]);
    expect(document.querySelector('#decode-output')?.textContent).toContain(
      'no standalone integrity or authentication check',
    );

    // Restore the honest state for any later interaction tests in this module.
    click('#encrypt-message');
    click('#decrypt-message');
  });
});

describe('lattice reduction interaction', () => {
  it('advances to a reduced basis when stepped to the end', () => {
    const step = document.querySelector('#lll-step') as HTMLButtonElement;
    let guard = 0;
    while (!step.disabled && guard < 100) {
      step.click();
      guard += 1;
    }
    expect(step.disabled).toBe(true);
    expect(document.querySelector('#lll-state')?.textContent).toMatch(/reduced/i);
  });
});
