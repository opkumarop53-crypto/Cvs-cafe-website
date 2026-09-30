const blobs = require('@netlify/blobs');
const { hashPassword, verifyPassword, makeToken, verifyToken } = require('./_shared.js');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-auth-token',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };
  const reply = (code, obj) => ({ statusCode: code, headers, body: JSON.stringify(obj) });

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  if (!process.env.AUTH_SECRET) {
    return reply(500, { error: 'Account sign-in is not set up on the server yet' });
  }

  try {
    if (typeof blobs.connectLambda === 'function') blobs.connectLambda(event);
    const users = blobs.getStore('cvs-users');

    if (event.httpMethod === 'GET') {
      const token = event.headers['x-auth-token'] || '';
      const payload = verifyToken(token, process.env.AUTH_SECRET);
      if (!payload) return reply(401, { error: 'Not logged in' });
      const user = await users.get(payload.email, { type: 'json' });
      if (!user) return reply(401, { error: 'Account no longer exists' });
      return reply(200, { ok: true, name: user.name, email: user.email });
    }

    if (event.httpMethod === 'POST') {
      const data = JSON.parse(event.body || '{}');
      const action = data.action;
      const email = String(data.email || '').trim().toLowerCase();
      const password = String(data.password || '');

      if (!EMAIL_RE.test(email)) return reply(400, { error: 'Please enter a valid email address' });
      if (password.length < 6) return reply(400, { error: 'Password must be at least 6 characters' });

      if (action === 'signup') {
        const name = String(data.name || '').trim().slice(0, 100);
        const phone = String(data.phone || '').trim().slice(0, 20);
        if (!name) return reply(400, { error: 'Please enter your name' });
        if (phone.replace(/\D/g, '').length < 10) return reply(400, { error: 'Please enter a valid phone number' });
        const existing = await users.get(email, { type: 'json' });
        if (existing) return reply(409, { error: 'An account with this email already exists — try logging in instead' });
        const user = { name: name, email: email, phone: phone, passwordHash: hashPassword(password), createdAt: new Date().toISOString() };
        await users.setJSON(email, user);
        const token = makeToken(email, process.env.AUTH_SECRET, 90);
        return reply(200, { ok: true, token: token, name: name, email: email });
      }

      if (action === 'forgot') {
        // No email service is connected, so password reset is verified by matching
        // the account's registered phone number instead of emailing a reset link.
        const phone = String(data.phone || '').trim();
        const last10 = (s) => s.replace(/\D/g, '').slice(-10);
        const user = await users.get(email, { type: 'json' });
        if (!user || !user.phone || last10(user.phone) !== last10(phone) || last10(phone).length < 10) {
          return reply(401, { error: 'We could not verify that email and phone number together. Double-check both match what you signed up with.' });
        }
        user.passwordHash = hashPassword(password);
        await users.setJSON(email, user);
        const token = makeToken(email, process.env.AUTH_SECRET, 90);
        return reply(200, { ok: true, token: token, name: user.name, email: user.email });
      }

      if (action === 'login') {
        const user = await users.get(email, { type: 'json' });
        if (!user || !verifyPassword(password, user.passwordHash)) {
          return reply(401, { error: 'Incorrect email or password' });
        }
        const token = makeToken(email, process.env.AUTH_SECRET, 90);
        return reply(200, { ok: true, token: token, name: user.name, email: user.email });
      }

      return reply(400, { error: 'Unknown action' });
    }

    return reply(405, { error: 'Method not allowed' });
  } catch (err) {
    return reply(500, { error: err.message });
  }
};
