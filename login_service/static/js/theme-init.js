// Applies the saved colour theme before the page is painted (a classic, blocking
// script: no inline scripts under the CSP). Light is the default; dark only when
// the visitor chose it. The system's light/dark setting is deliberately NOT
// followed (like AH Dashboard).
(function () {
  try {
    if (localStorage.getItem('ls_theme') === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  } catch (e) { /* storage unavailable: light */ }
})();
