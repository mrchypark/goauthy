(() => {
  'use strict';
  const cookieName = 'goauthy_ui_locale';
  const scriptPath = new URL(document.currentScript.src).pathname;
  const base = scriptPath.slice(0, -'/auth/v1/branding/locale.js'.length);
  let language = document.documentElement.lang === 'ko' ? 'ko' : 'en';
  const messages = {
     'Enter a device code': '기기 코드 입력', 'Language': '언어', 'Change language': '언어 변경', 'Keep editing': '계속 편집',
    'Sign in': '로그인', 'Username': '사용자 이름', 'Password': '비밀번호',
    'Continue to': '계속할 서비스:', 'Sign in with a passkey': '패스키로 로그인',
    'YOUR SECURE CONNECTION': '나만의 안전한 연결',
    'Complete the security key verification to continue.': '계속하려면 등록된 보안 키로 본인을 확인하세요.',
    'Continue with security key': '보안 키로 계속', 'or continue with': '또는',
    'Forgot password?': '비밀번호를 잊으셨나요?', 'Create an account': '계정 만들기',
    'Your access. In your hands.': '접근 권한은 언제나 내 손안에.',
    'Sign in to manage your account.': '내 계정을 관리하려면 로그인하세요.',
    'Sign in to review the code from your device. Signing in does not approve it.': '기기에 표시된 코드를 확인하려면 로그인하세요. 로그인만으로 접근이 승인되지는 않습니다.',
    'Sign in to review this connection handoff. Signing in does not approve it.': '연결 요청을 검토하려면 로그인하세요. 접근 권한은 검토 후 직접 승인합니다.',
    'You have unsaved changes. Change language and discard them?': '저장하지 않은 변경사항이 있습니다. 변경사항을 버리고 언어를 바꾸시겠습니까?'
  };
  function t(key, values = {}) {
    const text = language === 'ko' ? (Object.hasOwn(messages, key) ? messages[key] : key) : key;
    return text.replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match);
  }
  function translate(root = document) {
    root.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = el.getAttribute('data-brand-' + language) || el.getAttribute('data-brand-en') || t(el.getAttribute('data-i18n')); });
    root.querySelectorAll('[data-i18n-label]').forEach(el => { el.setAttribute('aria-label', t(el.getAttribute('data-i18n-label'))); });
  }
  let pending = 0;
  function setBusy(busy) {
    pending = Math.max(0, pending + (busy ? 1 : -1));
    document.querySelectorAll('[data-language-select]').forEach(select => { select.disabled = pending > 0; });
  }
  globalThis.GoAuthyI18n = {language, messages, t, translate, setBusy};
  document.addEventListener('DOMContentLoaded', () => {
    translate();
    let dirty = false;
    document.addEventListener('input', event => {
      if (event.target.matches('input,textarea,select') && !event.target.matches('[data-language-select]')) dirty = true;
    });
    document.querySelectorAll('[data-language-select]').forEach(select => {
      select.value = language;
      select.setAttribute('aria-label', t('Language'));
      select.addEventListener('change', () => {
        const next = select.value;
        if (pending || !['en', 'ko'].includes(next) || next === language) return;
        const inPlace = document.body.dataset.localeMode === 'in-place';
        if (dirty && !inPlace) {
          const dialog = document.createElement('dialog');
          dialog.className = 'locale-confirm';
          const message = document.createElement('p');
          message.id = 'locale-confirm-message';
          message.textContent = t('You have unsaved changes. Change language and discard them?');
          dialog.setAttribute('aria-labelledby', message.id);
          const cancel = document.createElement('button');
          cancel.type = 'button'; cancel.textContent = t('Keep editing');
          const proceed = document.createElement('button');
          proceed.type = 'button'; proceed.textContent = t('Change language');
          cancel.addEventListener('click', () => dialog.close());
          proceed.addEventListener('click', () => { dirty = false; dialog.close(); select.value = next; select.dispatchEvent(new Event('change')); });
          dialog.addEventListener('close', () => { select.value = language; dialog.remove(); });
          dialog.append(message, cancel, proceed);
          document.body.append(dialog);
          dialog.showModal();
          cancel.focus();
          return;
        }
        document.cookie = `${cookieName}=${next}; Path=${base}/; Max-Age=31536000; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
        if (inPlace) {
          language = next;
          globalThis.GoAuthyI18n.language = next;
          document.documentElement.lang = next;
          translate();
          select.setAttribute('aria-label', t('Language'));
        } else if (document.body.dataset.localeMode === 'reload') {
          location.reload();
        }
      });
    });
  });
})();
