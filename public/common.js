async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || 'เกิดข้อผิดพลาด'), { status: res.status, data });
  return data;
}

function formatTime(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function setBalance(sec) {
  const el = document.getElementById('balance');
  if (!el) return;
  el.textContent = '⏱ ' + formatTime(sec);
  el.classList.toggle('low', sec < 300);
}

// วาด header และคืนข้อมูลผู้ใช้ (null ถ้ายังไม่ login)
async function renderHeader() {
  const { user } = await api('/api/me');
  const nav = document.querySelector('header nav');
  if (user) {
    nav.innerHTML = `
      <span>👤 ${user.username}</span>
      <span class="balance" id="balance"></span>
      <a class="btn" href="/topup.html">เติมเงิน</a>
      <button class="btn secondary" id="logout">ออกจากระบบ</button>`;
    setBalance(user.balance_seconds);
    document.getElementById('logout').onclick = async () => {
      await api('/api/logout', {});
      location.href = '/';
    };
  } else {
    nav.innerHTML = `<a class="btn" href="/login.html">เข้าสู่ระบบ / สมัครสมาชิก</a>`;
  }
  return user;
}

function requireLogin(user) {
  if (!user) location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.search);
  return !!user;
}
