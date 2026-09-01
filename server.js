const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const keyId = process.env.RAZORPAY_KEY_ID;
const keySecret = process.env.RAZORPAY_KEY_SECRET;

let razorpay = null;
if (keyId && keySecret) {
  razorpay = new Razorpay({ key_id: keyId, key_secret: keySecret });
}

// Prices are kept on the server so customers cannot change the payment amount
// by editing browser JavaScript.
const PRODUCTS = {
  'Milk Chocolate': 199,
  'Almond Crunch': 249,
  'Kaju Makhana Royal Crunch': 299
};

app.get('/api/health', (req, res) => {
  res.json({ ok: true, razorpayConfigured: Boolean(razorpay) });
});

app.get('/api/config', (req, res) => {
  if (!keyId) return res.status(503).json({ error: 'Razorpay is not configured.' });
  res.json({ keyId });
});

app.post('/api/create-order', async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ error: 'Online payment is not configured yet.' });
    }

    const cart = Array.isArray(req.body.cart) ? req.body.cart : [];
    if (!cart.length) return res.status(400).json({ error: 'Cart is empty.' });

    let totalRupees = 0;
    for (const item of cart) {
      const price = PRODUCTS[item.name];
      const qty = Number(item.qty);
      if (!price || !Number.isInteger(qty) || qty < 1 || qty > 50) {
        return res.status(400).json({ error: 'Invalid product or quantity.' });
      }
      totalRupees += price * qty;
    }

    const order = await razorpay.orders.create({
      amount: totalRupees * 100,
      currency: 'INR',
      receipt: `bsbites_${Date.now()}`,
      notes: {
        customer_name: String(req.body.customer?.name || '').slice(0, 100),
        customer_phone: String(req.body.customer?.phone || '').slice(0, 20)
      }
    });

    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency
    });
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ error: 'Unable to create payment order.' });
  }
});

app.post('/api/verify-payment', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !keySecret) {
      return res.status(400).json({ verified: false, error: 'Missing payment details.' });
    }

    const expected = crypto
      .createHmac('sha256', keySecret)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    const verified = expected.length === razorpay_signature.length &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(razorpay_signature));

    if (!verified) {
      return res.status(400).json({ verified: false, error: 'Payment verification failed.' });
    }

    res.json({
      verified: true,
      payment_id: razorpay_payment_id,
      order_id: razorpay_order_id
    });
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ verified: false, error: 'Unable to verify payment.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`BS Bites running on port ${PORT}`);
});
