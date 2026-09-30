const crypto = require('crypto');

// ---- password hashing (Node's built-in scrypt, no extra package needed) ----
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---- session tokens: HMAC-signed, no server-side session storage needed ----
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
function sign(payloadStr, secret) {
  return b64url(crypto.createHmac('sha256', secret).update(payloadStr).digest());
}
function makeToken(email, secret, days) {
  const payload = JSON.stringify({ email: email, exp: Date.now() + (days || 90) * 86400000 });
  const p = b64url(Buffer.from(payload));
  return p + '.' + sign(p, secret);
}
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || token.indexOf('.') === -1) return null;
  const [p, sig] = token.split('.');
  if (sign(p, secret) !== sig) return null;
  try {
    const payload = JSON.parse(unb64url(p).toString());
    if (!payload.email || !payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, makeToken, verifyToken };
