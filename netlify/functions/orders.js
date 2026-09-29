const blobs = require('@netlify/blobs');

const STATUSES = ['processing', 'out_for_delivery', 'delivered'];

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-dashboard-token',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    'Content-Type': 'application/json'
  };
  const reply = (code, obj) => ({ statusCode: code, headers, body: JSON.stringify(obj) });

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  try {
    // Functions written in this "handler" style must connect to Blobs first.
    if (typeof blobs.connectLambda === 'function') blobs.connectLambda(event);
    const store = blobs.getStore('cvs-orders');

    // Any customer can place an order (no password).
    if (event.httpMethod === 'POST') {
      const data = JSON.parse(event.body || '{}');
      if (!data.name || !data.phone || !data.address) {
        return reply(400, { error: 'Please fill in name, phone and address' });
      }
      const loc = String(data.location_link || '');
      const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
      const order = {
        id: id,
        name: String(data.name).slice(0, 100),
        phone: String(data.phone).slice(0, 20),
        address: String(data.address).slice(0, 500),
        location_link: /^https:\/\/maps\.google\.com\//.test(loc) ? loc.slice(0, 300) : '',
        items: String(data.items || '').slice(0, 1000),
        total: String(data.total || '').slice(0, 50),
        payment: String(data.payment || '').slice(0, 30),
        status: 'processing',
        assignedTo: '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      await store.setJSON(id, order);
      return reply(200, { ok: true, id: id });
    }

    // Everything below is staff-only.
    if (!process.env.DASHBOARD_PASSWORD) {
      return reply(500, { error: 'Staff password is not set up on the server yet' });
    }
    const token = event.headers['x-dashboard-token'] || '';
    if (token !== process.env.DASHBOARD_PASSWORD) {
      return reply(401, { error: 'Unauthorized' });
    }

    if (event.httpMethod === 'GET') {
      const listing = await store.list();
      const orders = await Promise.all(listing.blobs.map((b) => store.get(b.key, { type: 'json' })));
      const clean = orders.filter(Boolean).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      return reply(200, { orders: clean });
    }

    if (event.httpMethod === 'PATCH') {
      const data = JSON.parse(event.body || '{}');
      if (!data.id) return reply(400, { error: 'Missing order id' });
      const existing = await store.get(String(data.id), { type: 'json' });
      if (!existing) return reply(404, { error: 'Order not found' });
      if (data.status) {
        if (STATUSES.indexOf(data.status) === -1) return reply(400, { error: 'Bad status' });
        existing.status = data.status;
      }
      if (typeof data.assignedTo === 'string') existing.assignedTo = data.assignedTo.slice(0, 60);
      existing.updatedAt = new Date().toISOString();
      await store.setJSON(existing.id, existing);
      return reply(200, { ok: true, order: existing });
    }

    return reply(405, { error: 'Method not allowed' });
  } catch (err) {
    return reply(500, { error: err.message });
  }
};

