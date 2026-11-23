// ShostaBazar client-side helpers. Loaded as an external file because the
// Content-Security-Policy forbids inline <script>. Client checks are UX only;
// every rule is enforced again on the server.
(function () {
  'use strict';

  // Show / hide password
  document.querySelectorAll('[data-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-toggle'));
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.setAttribute('aria-label', input.type === 'password' ? 'Show password' : 'Hide password');
    });
  });

  // Password policy checklist + strength meter
  var pw = document.querySelector('[data-strength]');
  if (pw) {
    var bar = document.getElementById('strength-bar');
    var confirm = document.getElementById('confirm');
    var hint = document.getElementById('match-hint');
    var rules = {
      length: function (v) { return v.length >= 8; },
      lower: function (v) { return /[a-z]/.test(v); },
      upper: function (v) { return /[A-Z]/.test(v); },
      digit: function (v) { return /[0-9]/.test(v); },
      special: function (v) { return /[^A-Za-z0-9]/.test(v); }
    };
    var update = function () {
      var v = pw.value;
      var score = 0;
      Object.keys(rules).forEach(function (k) {
        var ok = rules[k](v);
        if (ok) score++;
        var li = document.querySelector('#policy [data-rule="' + k + '"]');
        if (li) li.classList.toggle('ok', ok);
      });
      if (v.length >= 14 && score === 5) score = 5; else if (score === 5) score = 4;
      bar.className = 'strength-bar' + (v ? ' s' + Math.max(1, score) : '');
      if (confirm && hint) {
        if (!confirm.value) { hint.textContent = ''; hint.className = 'hint'; }
        else if (confirm.value === v) { hint.textContent = '✓ Passwords match'; hint.className = 'hint ok'; }
        else { hint.textContent = '✗ Passwords do not match'; hint.className = 'hint bad'; }
      }
    };
    pw.addEventListener('input', update);
    if (confirm) confirm.addEventListener('input', update);
  }

  // Confirmation dialogs for destructive actions
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.getAttribute('data-confirm'))) e.preventDefault();
    });
  });

  // Show stored UTC timestamps in the viewer's local time
  document.querySelectorAll('[data-utc]').forEach(function (el) {
    var d = new Date(el.getAttribute('data-utc'));
    if (!isNaN(d)) el.textContent = d.toLocaleString();
  });

  // Digits only in OTP inputs
  document.querySelectorAll('.otp-input').forEach(function (el) {
    el.addEventListener('input', function () { el.value = el.value.replace(/\D/g, '').slice(0, 6); });
  });

  // Idle timeout: the server already expires the session; this just moves the
  // user to the login page instead of leaving a stale screen open.
  var timeout = parseInt(document.body.getAttribute('data-idle-timeout'), 10);
  if (timeout > 0) {
    var timer;
    var reset = function () {
      clearTimeout(timer);
      timer = setTimeout(function () { window.location.href = '/login?timeout=1'; }, timeout * 1000 + 2000);
    };
    // Only page loads refresh the server session, so only reset on navigation-ish events.
    reset();
  }
})();
