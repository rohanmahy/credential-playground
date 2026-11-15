// SPEC §4 (desktop only): the native menu bar's shortcuts reach the
// frontend: File → New Tab (Ctrl+T), Close Tab (Ctrl+W), Open File…
// (Ctrl+O). Linux, so Ctrl rather than ⌘. The keys are real X events sent
// with xdotool, which exercise GTK's native accelerators; WebDriver key
// actions would not reach them. (The web build has no such shortcuts:
// browsers reserve them.)
import { execFileSync } from 'node:child_process';
import { browser } from '@wdio/globals';
import {
  appReady,
  detectedType,
  expectFieldText,
  expectThat,
  fixtureText,
  page,
  paste,
  tabBox,
  tabs,
} from '../helpers';

/** Ctrl+`key` as a real X keyboard event, so GTK's native accelerators
 *  see it: WebKitWebDriver's key actions are synthesized inside the web
 *  view and never reach them. Needs xdotool (scripts/linux-deps.sh --e2e). */
async function shortcut(key: string): Promise<void> {
  // Focus something inside the window first (the tab list).
  await page.getByRole('tablist', 'Credentials').click();
  execFileSync('xdotool', [
    'search',
    '--name',
    '^The Tokenator$',
    'windowfocus',
    '--sync',
    'key',
    '--clearmodifiers',
    `ctrl+${key}`,
  ]);
}

describe('desktop menu shortcuts', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
  });

  it('Ctrl+T opens a new empty tab', async () => {
    await paste(fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
    await expectThat(tabs()).toHaveCount(1);
    await shortcut('t');
    await expectThat(tabs()).toHaveCount(2);
    await expectThat(tabs().last()).toHaveAttribute('aria-selected', 'true');
    await expectFieldText(tabBox(), (t) => t === '', 'is empty');
    await expectThat(detectedType()).toHaveCount(0);
  });

  it('Ctrl+W closes the active tab', async () => {
    await shortcut('t');
    await expectThat(tabs()).toHaveCount(2);
    await shortcut('w');
    await expectThat(tabs()).toHaveCount(1);
    await shortcut('t');
    await shortcut('t');
    await expectThat(tabs()).toHaveCount(3);
    await shortcut('w');
    await expectThat(tabs()).toHaveCount(2);
  });

  it('the menu is native: no menu bar inside the page', async () => {
    await expectThat(page.getByRole('menubar')).toHaveCount(0);
  });

  // Last: Open File… shows the native file dialog, which WebDriver cannot
  // drive; the session (and the dialog) end with this spec file. The page
  // must not handle Ctrl+O itself (no tab change), and stays responsive.
  it('Ctrl+O asks the shell for a file and leaves the tabs alone', async () => {
    await shortcut('o');
    await browser.pause(1_000);
    await expectThat(tabs()).toHaveCount(1);
    await expectFieldText(tabBox(), (t) => t === '', 'is empty');
  });
});
