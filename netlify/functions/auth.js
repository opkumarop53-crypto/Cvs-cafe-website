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
