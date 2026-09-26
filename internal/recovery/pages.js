(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const base = document.body.dataset.base, mode = document.body.dataset.mode;
  const ko = document.documentElement.lang === 'ko';
  const words = (en, kr) => ko ? kr : en;
  const status = (text, error = false) => { const el = $('#page-status'); el.textContent = text; el.classList.toggle('auth-error', error); el.focus(); };
  const unknown = () => status(words('We could not confirm the result. Do not resubmit. Check your email or request a fresh link before starting again.', '결과를 확인하지 못했습니다. 다시 제출하지 마세요. 이메일을 확인하거나 새 링크를 요청한 뒤 다시 시작하세요.'), true);
  const api = (path, options = {}) => fetch(base + path, {credentials:'same-origin', cache:'no-store', ...options});
  const failure = (response) => words(response.status === 429 ? 'Too many attempts. Wait before trying again.' : 'This request could not be completed. Check the details or request a fresh link.', response.status === 429 ? '시도 횟수가 많습니다. 잠시 후 다시 시도하세요.' : '요청을 완료하지 못했습니다. 입력 내용을 확인하거나 새 링크를 요청하세요.');
  async function proof() {
    const response = await api('/auth/v1/pow', {method:'POST'});
    if (!response.ok) throw new Error(failure(response));
    const challenge = await response.text(), fields = challenge.split(':');
    const bits = Number(fields[1]), expires = Number(fields[2]) * 1000;
    if (fields.length !== 6 || fields[0] !== '1' || !Number.isInteger(bits) || bits < 10 || bits > 98 || !Number.isFinite(expires)) throw new Error(words('Invalid security challenge.', '보안 확인 요청이 올바르지 않습니다.'));
    const deadline = Math.min(expires, Date.now() + 60000), encoder = new TextEncoder();
    for (let n = 0; Date.now() < deadline; n++) {
      const solved = challenge + n;
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(solved)));
      let remaining = bits, valid = true;
      for (const byte of hash) { const count = Math.min(8, remaining); if ((byte >> (8 - count)) !== 0) { valid = false; break; } remaining -= count; if (!remaining) break; }
      if (valid) return solved;
    }
    throw new Error(words('Security check timed out. Please try again.', '보안 확인 시간이 초과되었습니다. 다시 시도하세요.'));
  }
  function json(method, data, headers = {}) { return {method, headers:{'Content-Type':'application/json', ...headers}, body:JSON.stringify(data)}; }
  const form = $('#request-form');
  async function initialize() {
    if (!form) return;
    if (!globalThis.crypto?.subtle) { status(words('Use a secure browser connection to continue.', '안전한 브라우저 연결에서 다시 시도하세요.'), true); return; }
    if (mode === 'register') {
      const response = await api('/auth/v1/users/values_config');
      if (!response.ok) throw new Error(failure(response));
      const policy = await response.json();
      const optional = document.createElement('details'), summary = document.createElement('summary');
      summary.textContent = words('Add optional details', '선택 정보 추가'); optional.append(summary);
      const fields = [['preferred_username','Username','사용자 이름'],['given_name','Given name','이름'],['family_name','Family name','성'],['birthdate','Birthdate','생년월일'],['phone','Phone','전화번호'],['street','Street','주소'],['zip','Postal code','우편번호'],['city','City','도시'],['country','Country','국가'],['tz','Timezone','시간대']];
      for (const [name,en,kr] of fields) {
        const rule = name === 'preferred_username' ? policy.preferred_username?.preferred_username : policy[name];
        if (rule === 'hidden') continue;
        const label = document.createElement('label'), input = document.createElement('input');
        label.textContent = words(en,kr) + (rule === 'required' ? ' *' : words(' (optional)',' (선택)'));
        input.name = name; input.required = rule === 'required'; input.maxLength = 128;
        if (name === 'birthdate') input.type = 'date';
        if (name === 'phone') { input.type = 'tel'; input.placeholder = '+821012345678'; }
        if (name === 'preferred_username' && policy.preferred_username?.pattern_html) input.pattern = policy.preferred_username.pattern_html;
        label.append(input); (rule === 'required' ? $('#registration-fields') : optional).append(label);
      }
      if (optional.children.length > 1) $('#registration-fields').append(optional);
    }
    form.querySelector('button').disabled = false;
  }
  if (form) form.addEventListener('submit', async (event) => {
    event.preventDefault(); const button = form.querySelector('button'); if (button.disabled) return; button.disabled = true;
    globalThis.GoAuthyI18n?.setBusy?.(true);
    let submitted = false;
    status(words('Preparing your request…', '요청을 준비하고 있습니다…'));
    try {
      const data = Object.fromEntries(new FormData(form));
      data.pow = await proof();
      if (mode === 'register') {
        data.user_values = {};
        for (const key of ['birthdate','phone','street','zip','city','country','tz']) { if (data[key]) data.user_values[key] = data[key]; delete data[key]; }
        for (const key of ['preferred_username','given_name','family_name']) if (!data[key]) delete data[key];
      }
      submitted = true;
      const response = await api(mode === 'register' ? '/auth/v1/users/register' : '/auth/v1/users/request_reset', json('POST',data));
      if (!response.ok) { if (response.status < 500) submitted = false; throw new Error(failure(response)); }
      form.hidden = true;
      status(words('Check your inbox. If this address is eligible, an email with the next steps will arrive shortly. You can close this tab.', '받은편지함을 확인하세요. 요청 가능한 주소라면 다음 단계가 담긴 이메일이 도착합니다. 이 탭을 닫아도 됩니다.'));
    } catch (error) { if (submitted) unknown(); else { status(error.message,true); button.disabled = false; } } finally { globalThis.GoAuthyI18n?.setBusy?.(false); }
  });
  const start = $('#reset-start'), reset = $('#reset-form');
  let csrf = '', resetPath = '', token = '';
  if (start) start.addEventListener('click', async () => {
    start.disabled = true;
    globalThis.GoAuthyI18n?.setBusy?.(true);
    try {
      const path = location.pathname.slice(base.length), segments = path.split('/');
      token = decodeURIComponent(segments.pop()); segments.pop(); resetPath = segments.join('/') + '/reset';
      const response = await api(path, {headers:{Accept:'application/json'}});
      if (!response.ok) throw new Error(failure(response));
      const data = await response.json(); csrf = data.csrf_token;
      const p = data.password_policy;
      if (!csrf || !p) throw new Error(words('The link could not be verified.', '링크를 확인하지 못했습니다.'));
      $('#password-policy').textContent = words(`Use ${p.length_min}–${p.length_max} characters; at least ${p.lower_case} lowercase, ${p.upper_case} uppercase, ${p.digits} digits and ${p.special} special characters. Previously used passwords may be rejected.`, `${p.length_min}~${p.length_max}자, 소문자 ${p.lower_case}개·대문자 ${p.upper_case}개·숫자 ${p.digits}개·특수문자 ${p.special}개 이상을 사용하세요. 이전 비밀번호는 거부될 수 있습니다.`);
      start.hidden = true; reset.hidden = false; reset.elements.password.focus();
    } catch (error) { status(error.message,true); } finally { globalThis.GoAuthyI18n?.setBusy?.(false); }
  });
  if (reset) reset.addEventListener('submit', async (event) => {
    event.preventDefault(); const button = reset.querySelector('button'); if (button.disabled) return;
    if (reset.elements.password.value !== reset.elements.confirm.value) { status(words('Passwords do not match.', '비밀번호가 일치하지 않습니다.'),true); return; }
    button.disabled = true;
    globalThis.GoAuthyI18n?.setBusy?.(true);
    try {
      const response = await api(resetPath, json('PUT',{magic_link_id:token,password:reset.elements.password.value},{'X-Pwd-CSRF-Token':csrf}));
      if (response.status !== 202) { if (response.status >= 500) { reset.reset(); unknown(); } else { status(failure(response),true); button.disabled = false; } return; }
      reset.reset(); reset.hidden = true; csrf = ''; token = '';
      status(words('Password saved. Return to your app and sign in with your new password.', '비밀번호를 저장했습니다. 앱으로 돌아가 새 비밀번호로 로그인하세요.'));
    } catch { reset.reset(); unknown(); } finally { globalThis.GoAuthyI18n?.setBusy?.(false); }
  });
  initialize().catch((error) => status(error.message,true));
})();
