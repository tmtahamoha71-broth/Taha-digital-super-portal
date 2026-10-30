'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_PIN_HASH = process.env.ADMIN_PIN_HASH;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY ||
    !SESSION_SECRET || !ADMIN_PIN_HASH) {
  console.error('Missing required environment variables.');
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false
});

const submitLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false
});

const BUCKET = 'advertising-uploads';

function makeToken() {
  const payload = {
    admin: true,
    exp: Date.now() + (8 * 60 * 60 * 1000)
  };

  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('base64url');

  return body + '.' + signature;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;

  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(parts[0])
    .digest();

  let received;
  try {
    received = Buffer.from(parts[1], 'base64url');
  } catch {
    return false;
  }

  if (received.length !== expected.length) return false;

  if (!crypto.timingSafeEqual(received, expected)) return false;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString()
    );

    return payload.admin === true && payload.exp > Date.now();
  } catch {
    return false;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie || '';

  const item = header
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith(name + '='));

  return item ? decodeURIComponent(item.slice(name.length + 1)) : '';
}

function requireAdmin(req, res, next) {
  const token = getCookie(req, 'tm_admin');

  if (!verifyToken(token)) {
    return res.status(401).json({
      success: false,
      message: 'የአስተዳዳሪ ፈቃድ ያስፈልጋል።'
    });
  }

  next();
}

function hashOtp(value) {
  return crypto
    .createHash('sha256')
    .update(value)
    .digest('hex');
}

function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function clean(value, max = 1000) {
  return String(value || '').trim().slice(0, max);
}

async function uploadFile(file, folder, requestId) {
  if (!file || !file.buffer) return null;

  const allowed = [
    'image/jpeg',
    'image/png',
    'image/webp',
    'application/pdf'
  ];

  if (!allowed.includes(file.mimetype)) {
    throw new Error('የፋይሉ ዓይነት አይፈቀድም።');
  }

  if (file.size > 5 * 1024 * 1024) {
    throw new Error('ፋይሉ ከ5 MB በላይ ነው።');
  }

  const ext = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'application/pdf': 'pdf'
  }[file.mimetype];

  const path = `applications/${requestId}/${folder}-${crypto.randomUUID()}.${ext}`;

  const { error } = await supabase.storage
    .from(BUCKET)
    .upload(path, file.buffer, {
      contentType: file.mimetype,
      upsert: false
    });

  if (error) throw error;

  return path;
}

async function createSignedFileUrl(path) {
  if (!path) return null;

  const { data, error } = await supabase.storage
    .from(BUCKET)
    .createSignedUrl(path, 60 * 10);

  if (error) return null;

  return data.signedUrl;
}

async function sendAdminWhatsApp(message) {
  const token = process.env.WHATSAPP_ACCESS_TOKEN;
  const phoneId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const adminPhone = process.env.WHATSAPP_ADMIN_NUMBER;

  if (!token || !phoneId || !adminPhone) {
    return { sent: false, reason: 'WhatsApp API not configured' };
  }

  const response = await fetch(
    `https://graph.facebook.com/v23.0/${phoneId}/messages`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: adminPhone,
        type: 'text',
        text: { body: message }
      })
    }
  );

  if (!response.ok) {
    const error = await response.text();
    console.error('WhatsApp API error:', error);
    return { sent: false };
  }

  return { sent: true };
}

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    service: 'Ethio Digital Super Portal',
    status: 'running'
  });
});

/* PUBLIC AD SUBMISSION */

app.post('/api/ads', submitLimiter, async (req, res) => {
  try {
    const {
      business_name,
      contact_name,
      contact_phone,
      ad_type,
      duration,
      budget_etb,
      details,
      payment_method,
      transaction_reference
    } = req.body || {};

    if (!clean(business_name, 150) ||
        !clean(contact_phone, 40) ||
        !clean(details, 4000)) {
      return res.status(400).json({
        success: false,
        message: 'የግዴታ መረጃዎችን ያስገቡ።'
      });
    }

    const id = crypto.randomUUID();

    const { data, error } = await supabase
      .from('portal_ad_requests')
      .insert({
        id,
        business_name: clean(business_name, 150),
        contact_name: clean(contact_name, 150),
        contact_phone: clean(contact_phone, 40),
        ad_type: clean(ad_type, 100),
        duration: clean(duration, 100),
        budget_etb: Number.isFinite(Number(budget_etb))
          ? Number(budget_etb)
          : null,
        details: clean(details, 4000),
        payment_method: clean(payment_method, 80),
        transaction_reference: clean(transaction_reference, 150),
        status: 'pending',
        payment_status: 'pending'
      })
      .select('id')
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      request_id: data.id,
      message: 'ማመልከቻው ተመዝግቧል።'
    });

  } catch (error) {
    console.error('Ad submission error:', error);

    res.status(500).json({
      success: false,
      message: 'ማመልከቻውን መመዝገብ አልተቻለም።'
    });
  }
});

/* PUBLIC ACTIVE ADS */

app.get('/api/ads/active', async (req, res) => {
  try {
    const now = new Date().toISOString();

    const { data, error } = await supabase
      .from('portal_ad_requests')
      .select('id,business_name,ad_type,details,ad_image_path,starts_at,ends_at')
      .eq('status', 'approved')
      .eq('payment_status', 'verified')
      .lte('starts_at', now)
      .gte('ends_at', now)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const ads = await Promise.all(
      (data || []).map(async ad => ({
        ...ad,
        image_url: await createSignedFileUrl(ad.ad_image_path)
      }))
    );

    res.json({ success: true, ads });

  } catch (error) {
    console.error('Active ads error:', error);

    res.status(500).json({
      success: false,
      message: 'ማስታወቂያዎችን ማምጣት አልተቻለም።'
    });
  }
});

/* ADMIN LOGIN */

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const pin = clean(req.body?.pin, 100);

    if (!pin || pin.length < 4 || pin.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'ትክክለኛ PIN ያስገቡ።'
      });
    }

    const valid = await bcrypt.compare(pin, ADMIN_PIN_HASH);

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: 'የአስተዳዳሪ PIN ትክክል አይደለም።'
      });
    }

    res.setHeader('Set-Cookie',
      `tm_admin=${encodeURIComponent(makeToken())}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
    );

    res.json({
      success: true,
      message: 'የአስተዳዳሪ መግቢያ ተሳክቷል።'
    });

  } catch (error) {
    console.error('Admin login error:', error);

    res.status(500).json({
      success: false,
      message: 'መግባት አልተቻለም።'
    });
  }
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  res.setHeader('Set-Cookie',
    'tm_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
  );

  res.json({ success: true });
});

/* ADMIN REQUEST LIST */

app.get('/api/admin/requests', requireAdmin, adminLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('portal_ad_requests')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) throw error;

    const requests = await Promise.all(
      (data || []).map(async item => ({
        ...item,
        logo_url: await createSignedFileUrl(item.logo_path),
        receipt_url: await createSignedFileUrl(item.receipt_path)
      }))
    );

    res.json({ success: true, requests });

  } catch (error) {
    console.error('Admin list error:', error);

    res.status(500).json({
      success: false,
      message: 'የማመልከቻ ዝርዝሩን ማምጣት አልተቻለም።'
    });
  }
});

/* ISSUE A UNIQUE OTP FOR ONE REQUEST */

app.post('/api/admin/requests/:id/issue-otp',
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    try {
      const id = clean(req.params.id, 60);
      const otp = generateOtp();
      const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();

      const { data: request, error: findError } = await supabase
        .from('portal_ad_requests')
        .select('id,business_name,status')
        .eq('id', id)
        .single();

      if (findError || !request || request.status !== 'pending') {
        return res.status(404).json({
          success: false,
          message: 'የሚጠበቀው ማመልከቻ አልተገኘም።'
        });
      }

      const { error } = await supabase
        .from('portal_ad_requests')
        .update({
          otp_hash: hashOtp(otp),
          otp_expires_at: expires,
          otp_used_at: null
        })
        .eq('id', id)
        .eq('status', 'pending');

      if (error) throw error;

      const message =
        `TM Studio Admin OTP\n` +
        `Request: ${id}\n` +
        `Business: ${request.business_name}\n` +
        `OTP: ${otp}\n` +
        `Expires in 5 minutes.\n` +
        `Do not share this code.`;

      const wa = await sendAdminWhatsApp(message);

      res.json({
        success: true,
        whatsapp_sent: wa.sent,
        otp: wa.sent ? undefined : otp,
        message: wa.sent
          ? 'OTP ወደ አስተዳዳሪው WhatsApp ተልኳል።'
          : 'OTP በዚህ የተጠበቀ የአስተዳዳሪ ገጽ ላይ ታይቷል።'
      });

    } catch (error) {
      console.error('OTP error:', error);

      res.status(500).json({
        success: false,
        message: 'OTP ማዘጋጀት አልተቻለም።'
      });
    }
  }
);

/* VERIFY PAYMENT AND APPROVE AD */

app.post('/api/admin/requests/:id/approve',
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    try {
      const id = clean(req.params.id, 60);
      const otp = clean(req.body?.otp, 6);

      if (!/^\d{6}$/.test(otp)) {
        return res.status(400).json({
          success: false,
          message: 'ባለ6 አሃዝ OTP ያስገቡ።'
        });
      }

      const { data: request, error } = await supabase
        .from('portal_ad_requests')
        .select('*')
        .eq('id', id)
        .single();

      if (error || !request) {
        return res.status(404).json({
          success: false,
          message: 'ማመልከቻው አልተገኘም።'
        });
      }

      if (request.status !== 'pending') {
        return res.status(409).json({
          success: false,
          message: 'ይህ ማመልከቻ ቀድሞ ተ处理ሯል።'
        });
      }

      if (request.payment_status !== 'verified') {
        return res.status(400).json({
          success: false,
          message: 'ክፍያው ከመረጋገጡ በፊት ማስታወቂያውን ማጽደቅ አይቻልም።'
        });
      }

      if (!request.otp_hash ||
          !request.otp_expires_at ||
          request.otp_used_at ||
          new Date(request.otp_expires_at).getTime() < Date.now() ||
          hashOtp(otp) !== request.otp_hash) {
        return res.status(401).json({
          success: false,
          message: 'OTP ትክክል አይደለም ወይም ጊዜው አልፏል።'
        });
      }

      const now = new Date().toISOString();
      const end = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();

      const { data: updated, error: updateError } = await supabase
        .from('portal_ad_requests')
        .update({
          status: 'approved',
          otp_used_at: now,
          starts_at: now,
          ends_at: end,
          approved_at: now
        })
        .eq('id', id)
        .eq('status', 'pending')
        .eq('payment_status', 'verified')
        .is('otp_used_at', null)
        .select('id')
        .maybeSingle();

      if (updateError) throw updateError;

      if (!updated) {
        return res.status(409).json({
          success: false,
          message: 'ማመልከቻው በሌላ ሂደት ተፈትሿል።'
        });
      }

      await supabase.from('portal_admin_audit').insert({
        request_id: id,
        action: 'approved',
        created_at: now
      });

      res.json({
        success: true,
        message: 'ክፍያው ተረጋግጦ ማስታወቂያው ጸድቋል።'
      });

    } catch (error) {
      console.error('Approval error:', error);

      res.status(500).json({
        success: false,
        message: 'ማጽደቅ አልተቻለም።'
      });
    }
  }
);

/* PAYMENT VERIFICATION — ADMIN ONLY */

app.post('/api/admin/requests/:id/verify-payment',
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    try {
      const id = clean(req.params.id, 60);
      const reference = clean(req.body?.reference, 150);

      if (!reference) {
        return res.status(400).json({
          success: false,
          message: 'የግብይት ማጣቀሻ ያስገቡ።'
        });
      }

      const { data, error } = await supabase
        .from('portal_ad_requests')
        .update({
          payment_status: 'verified',
          verified_at: new Date().toISOString()
        })
        .eq('id', id)
        .eq('status', 'pending')
        .eq('payment_status', 'pending')
        .eq('transaction_reference', reference)
        .select('id')
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        return res.status(409).json({
          success: false,
          message: 'ማጣቀሻው አልተዛመደም ወይም ጥያቄው ቀድሞ ተረጋግጧል።'
        });
      }

      await supabase.from('portal_admin_audit').insert({
        request_id: id,
        action: 'payment_verified',
        created_at: new Date().toISOString()
      });

      res.json({
        success: true,
        message: 'የክፍያ ሁኔታው ተረጋግጧል። አሁን OTP አውጥተው ማጽደቅ ይችላሉ።'
      });

    } catch (error) {
      console.error('Payment verification error:', error);

      res.status(500).json({
        success: false,
        message: 'ክፍያውን ማረጋገጥ አልተቻለም።'
      });
    }
  }
);

/* SERVE THE EXISTING PORTAL */

app.use(express.static(process.cwd(), {
  index: 'index.html',
  dotfiles: 'deny'
}));

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'የተጠየቀው አድራሻ አልተገኘም።'
  });
});

app.listen(PORT, () => {
  console.log(`Ethio Digital Super Portal running on port ${PORT}`);
});
