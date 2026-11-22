import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TEXTS, setLang, t } from '../../login_service/static/js/i18n.js';

test('English and Dutch have the same keys', () => {
  assert.deepEqual(Object.keys(TEXTS.en).sort(), Object.keys(TEXTS.nl).sort());
});

test('t() falls back to "" for unknown keys and switches language', () => {
  setLang('en');
  assert.equal(t('signOut'), 'Sign out');
  setLang('nl');
  assert.equal(t('signOut'), 'Uitloggen');
  assert.equal(t('no-such-key'), '');
});
