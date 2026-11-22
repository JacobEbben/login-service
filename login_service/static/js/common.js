// @ts-check
// Shared by every page: config, storage, language, theme and formatting.
// DOM is built with createElement/textContent only (the CSP requires Trusted
// Types for scripts, so assigning HTML strings would be refused anyway).
import { t, setLang, lang } from './i18n.js';


export const storage = {
  /** @param {string} key */
  get(key) { try { return localStorage.getItem('ls_' + key); } catch { return null; } },
  /** @param {string} key @param {string|null} value */
  set(key, value) {
    try { if (value === null) localStorage.removeItem('ls_' + key); else localStorage.setItem('ls_' + key, value); } catch { /* blocked */ }
  },
  /** @param {string} key @param {any} fallback */
  getJSON(key, fallback) { try { return JSON.parse(this.get(key) || '') ?? fallback; } catch { return fallback; } },
  /** @param {string} key @param {any} value */
  setJSON(key, value) { this.set(key, JSON.stringify(value)); },
};

/** @param {string} id @returns {any} */
export const $ = id => document.getElementById(id);

/**
 * A new element. @param {string} tag @param {{[k: string]: any}} [props] @param {(Node|string)[]} [children]
 * @returns {any}
 */
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(c);
  return node;
}

/** @param {number} n */
export function fmtBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i && v < 10 ? 1 : 0)} ${units[i]}`;
}

/** @param {number} ts seconds */
export function fmtDate(ts) {
  return new Date(ts * 1000).toLocaleString(lang() === 'nl' ? 'nl-NL' : 'en-GB',
    { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

/** Translate data-i18n elements and format data-ts / data-bytes. @param {ParentNode} [root] */
export function applyTexts(root = document) {
  document.documentElement.lang = lang();
  // Statement pages hold their text in both languages: show the visitor's.
  for (const node of root.querySelectorAll('[data-setlang]')) {
    node.setAttribute('aria-pressed', String(/** @type {HTMLElement} */ (node).dataset.setlang === lang()));
  }
  for (const node of root.querySelectorAll('[data-lang]')) {
    /** @type {HTMLElement} */ (node).hidden = /** @type {HTMLElement} */ (node).dataset.lang !== lang();
  }
  for (const node of root.querySelectorAll('[data-i18n]')) {
    const text = t(/** @type {HTMLElement} */ (node).dataset.i18n || '');
    if (text) node.textContent = text;
  }
  for (const node of root.querySelectorAll('[data-i18n-aria]')) node.setAttribute('aria-label', t(/** @type {HTMLElement} */ (node).dataset.i18nAria || ''));
  for (const node of root.querySelectorAll('[data-i18n-ph]')) node.setAttribute('placeholder', t(/** @type {HTMLElement} */ (node).dataset.i18nPh || ''));
  for (const node of root.querySelectorAll('[data-i18n-title]')) node.setAttribute('title', t(/** @type {HTMLElement} */ (node).dataset.i18nTitle || ''));
  for (const node of root.querySelectorAll('time[data-ts]')) {
    const ts = Number(/** @type {HTMLElement} */ (node).dataset.ts);
    node.textContent = fmtDate(ts);
    node.setAttribute('datetime', new Date(ts * 1000).toISOString());
  }
  for (const node of root.querySelectorAll('[data-bytes]')) node.textContent = fmtBytes(Number(/** @type {HTMLElement} */ (node).dataset.bytes));
}

/** Error code from the API -> a sentence. @param {any} err */
export function errorText(err) {
  const code = err && err.code ? err.code : 'network';
  return t('err_' + code) || t('err_generic');
}

/** @param {(() => void)[]} onLang */
export function initPage(...onLang) {
  const langSel = $('langSelect'), themeSel = $('themeSelect');
  const saved = storage.get('lang');
  setLang(saved === 'nl' || saved === 'en' ? saved : (navigator.language || '').toLowerCase().startsWith('nl') ? 'nl' : 'en');
  if (langSel) {
    langSel.value = lang();
    langSel.addEventListener('change', () => {
      setLang(langSel.value); storage.set('lang', langSel.value);
      applyTexts(); onLang.forEach(f => f());
    });
  }
  // NL / EN bar on the statement pages (they have no header with the language menu).
  for (const btn of document.querySelectorAll('[data-setlang]')) {
    btn.addEventListener('click', () => {
      const v = /** @type {HTMLElement} */ (btn).dataset.setlang || 'nl';
      setLang(v); storage.set('lang', v);
      applyTexts(); onLang.forEach(f => f());
    });
  }
  if (themeSel) {
    themeSel.value = storage.get('theme') === 'dark' ? 'dark' : 'light';
    themeSel.addEventListener('change', () => {
      const dark = themeSel.value === 'dark';
      storage.set('theme', dark ? 'dark' : null);
      if (dark) document.documentElement.setAttribute('data-theme', 'dark');
      else document.documentElement.removeAttribute('data-theme');
    });
  }
  // Copy buttons: data-copy="<id of the input>".
  for (const btn of document.querySelectorAll('[data-copy]')) {
    btn.addEventListener('click', async () => {
      const input = /** @type {HTMLInputElement|null} */ (document.getElementById(/** @type {HTMLElement} */ (btn).dataset.copy || ''));
      if (!input) return;
      const ok = await copyText(input.value.replace(/\s+/g, input.classList.contains('mono') && input.id === 'setupKey' ? '' : ' '));
      btn.textContent = ok ? t('copied') : t('copyFailed');
    });
  }
  // Buttons that need a confirmation (admin forms).
  for (const btn of document.querySelectorAll('[data-confirm]')) {
    btn.addEventListener('click', e => {
      if (!confirm(t(/** @type {HTMLElement} */ (btn).dataset.confirm || ''))) e.preventDefault();
    });
  }
  applyTexts();
}

/**
 * fetch() for the JSON API: throws {code, status} on errors.
 * @param {string} url @param {RequestInit} [opts]
 */
export async function api(url, opts = {}) {
  const res = await fetch(url, { credentials: 'same-origin', ...opts });
  if (!res.ok) {
    let code = 'generic';
    try { code = (await res.json()).error || code; } catch { /* not JSON */ }
    throw Object.assign(new Error(code), { code, status: res.status });
  }
  return res;
}

/** @param {string} text */
export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

