// Cloudflare Worker: quiz / summary / flashcards / Q&A generator for lectures,
// using the free Gemini API, with KV caching and simple score tracking.
//
// SETUP:
// 1. Get a free Gemini key at https://aistudio.google.com/apikey
//    Settings -> Variables and Secrets -> add GEMINI_API_KEY (type: Secret)
// 2. Create a KV namespace (Storage & Databases -> KV -> Create, name it
//    anything e.g. "quiz-kv"), then bind it to this Worker:
//    Settings -> Bindings -> Add -> KV Namespace -> variable name: QUIZ_KV
// 3. Change ALLOWED_ORIGIN below to your app's real domain before going live.
// 4. In Firebase Console -> Authentication -> Sign-in method, enable the
//    "Anonymous" provider. The public quiz ("نتايجي") now signs each
//    visitor's device into Firebase anonymously (see quizAuth in
//    index.html) so save_score/get_scores can verify a real, unforgeable
//    per-device identity without requiring any login - if Anonymous sign-in
//    isn't enabled, those calls will fail with an auth error.

const ALLOWED_ORIGIN = 'https://justm.site';
const BUILD_VERSION = 'v5.6-ai-video-v20.11-resume-download-totp-fix';
const GEMINI_MODEL = 'gemini-2.5-flash';
const CACHE_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

// V20.2.1 generated-video download:
// Set these as Cloudflare Worker Secrets (NOT client-side variables):
//   CLOUDINARY_CLOUD_NAME
//   CLOUDINARY_API_KEY
//   CLOUDINARY_API_SECRET
// The generated-video upload endpoint verifies a real Firebase user before
// signing the Cloudinary upload, so the browser never receives the API secret.

// These two identify the Firebase project so this Worker can verify an
// admin's ID token itself (see verifyOwner below). The project ID is public.
// The API key is NOT in this file (this repo is public): it lives in a
// Cloudflare Secret named FIREBASE_WEB_API_KEY, read as env.FIREBASE_WEB_API_KEY.
// It is a separate server-side key restricted to the Identity Toolkit API only,
// not the browser key in the site's firebaseConfig.
// Settings -> Variables and Secrets -> add FIREBASE_WEB_API_KEY (type: Secret)
const FIREBASE_PROJECT_ID = 'hissgiza-8fa57';

// FIX (was the most serious issue in this file): get_ai_log / get_banned /
// ban_user / unban_user used to run with NO server-side check at all -
// anyone who found this Worker's URL could dump the student Q&A log
// (names + IPs + questions) or ban/unban any IP, entirely bypassing the
// admin login on the website. This function makes the Worker verify the
// caller for itself instead of trusting the client:
//   1) the caller must send "Authorization: Bearer <Firebase ID token>"
//   2) that token is checked against Firebase Auth itself (accounts:lookup)
//      to get the real signed-in uid - a forged/expired token fails here
//   3) that uid's admin_accounts/{uid} doc is read via the Firestore REST
//      API using the SAME token, so Firestore's own security rules (which
//      only let a user read their own admin_accounts doc) do the actual
//      enforcement - this Worker never needs its own service-account key
//   4) only a doc with role == "owner" is accepted, matching the fact
//      the admin dashboard already treats this whole section (aiUsageBox)
//      as owner-only
async function verifyOwner(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return null;
  const idToken = match[1];
  if (!env || !env.FIREBASE_WEB_API_KEY) return null; // secret not configured -> deny

  let uid;
  try {
    const lookupRes = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${env.FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );
    if (!lookupRes.ok) return null;
    const lookupData = await lookupRes.json();
    uid = lookupData.users && lookupData.users[0] && lookupData.users[0].localId;
  } catch (e) {
    return null;
  }
  if (!uid) return null;

  try {
    const docRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/admin_accounts/${uid}`,
      { headers: { Authorization: `Bearer ${idToken}` } }
    );
    if (!docRes.ok) return null; // not an admin, or token doesn't match this uid's own doc
    const docData = await docRes.json();
    const role = docData.fields && docData.fields.role && docData.fields.role.stringValue;
    return { uid, role: role || 'admin' };
  } catch (e) {
    return null;
  }
}

// Verifies that the caller sent a genuine Firebase ID token issued by THIS
// project - accounts:lookup only succeeds for a real, currently-valid token,
// so this can't be forged the way a client-supplied name/id string could.
// Deliberately does NOT require any Firestore doc to exist for the uid:
// used for the public quiz-scoring endpoints (save_score/get_scores), which
// run on the no-login public lectures list and must also accept a device's
// anonymous Firebase identity, not just a real course/admin account.
async function verifyRealUser(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match || !env || !env.FIREBASE_WEB_API_KEY) return null;
  const idToken = match[1];
  try {
    const lookupRes = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${env.FIREBASE_WEB_API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }) }
    );
    if (!lookupRes.ok) return null;
    const data = await lookupRes.json();
    const uid = data.users && data.users[0] && data.users[0].localId;
    return uid ? { uid } : null;
  } catch (e) {
    return null;
  }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    // Authorization is needed for the owner-only calls (get_ai_log, get_banned,
    // ban_user, unban_user): without it the browser's CORS preflight rejects the
    // request and the site just shows "Failed to fetch".
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function slug(s) {
  return (s || '').toString().trim().toLowerCase().replace(/\s+/g, '_').slice(0, 80);
}

// Simple per-IP rate limit backed by KV (approximate — KV reads/writes aren't
// atomic, so under heavy simultaneous load a few extra requests may slip
// through, but that's fine for our purpose of stopping one person from
// burning through the whole day's free Gemini quota alone).
const RATE_LIMIT_PER_MINUTE = 6;
const RATE_LIMIT_PER_DAY = 60;

async function checkRateLimit(env, ip) {
  if (!env.QUIZ_KV || !ip) return null; // fail open if KV or IP unavailable

  const minuteKey = 'rl:min:' + ip;
  const dayKey = 'rl:day:' + ip;

  const [minuteRaw, dayRaw] = await Promise.all([
    env.QUIZ_KV.get(minuteKey),
    env.QUIZ_KV.get(dayKey),
  ]);
  const minuteCount = minuteRaw ? parseInt(minuteRaw) : 0;
  const dayCount = dayRaw ? parseInt(dayRaw) : 0;

  if (minuteCount >= RATE_LIMIT_PER_MINUTE) {
    return 'كتّرت الطلبات في دقيقة واحدة — استنى دقيقة وجرب تاني.';
  }
  if (dayCount >= RATE_LIMIT_PER_DAY) {
    return 'وصلت للحد الأقصى من طلبات الذكاء الاصطناعي المسموحة لك اليوم — جرب تاني بكرة.';
  }

  await Promise.all([
    env.QUIZ_KV.put(minuteKey, String(minuteCount + 1), { expirationTtl: 60 }),
    env.QUIZ_KV.put(dayKey, String(dayCount + 1), { expirationTtl: 60 * 60 * 24 }),
  ]);
  return null; // allowed
}


// ---------------------------------------------------------------------------
// Course-video analysis (owner only). The courses Worker owns the private R2
// bucket, so this Worker never sees a raw R2 url: the owner's browser mints a
// short-lived stream token from the courses Worker and sends the resulting
// stream url here. Only that exact origin is ever fetched (no SSRF).
// ---------------------------------------------------------------------------
const COURSES_WORKER_ORIGIN = 'https://justm-courses.wolfiiiiiiiiiiii7.workers.dev';
const MAX_VIDEO_BYTES = 400 * 1024 * 1024;   // refuse anything larger
const BUFFER_VIDEO_BYTES = 50 * 1024 * 1024; // <= this: buffer, > this: stream
const GEMINI_FILES_BASE = 'https://generativelanguage.googleapis.com';

function isAllowedVideoUrl(u) {
  try {
    const url = new URL(u);
    return url.origin === COURSES_WORKER_ORIGIN && url.searchParams.get('action') === 'stream';
  } catch (e) { return false; }
}

// Plain-text Gemini call (callGemini forces JSON output).
// Bump a mode's version whenever its prompt changes: cached results are keyed
// by content + mode only, so without this the OLD cached answer keeps being served.
const PROMPT_VERSIONS = { video_script: '3', video_explain: '10', video_brain: '1' };

async function callGeminiText(env, parts) {
  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
  const r = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
    body: JSON.stringify({ contents: [{ role: 'user', parts }] }),
  });
  if (!r.ok) {
    const err = new Error('Gemini API error: ' + (await r.text()));
    err.status = r.status;
    throw err;
  }
  const data = await r.json();
  const blockReason = data.promptFeedback && data.promptFeedback.blockReason;
  if (blockReason) { const err = new Error('Gemini blocked this content (' + blockReason + ')'); err.status = 422; throw err; }
  const text = (data.candidates && data.candidates[0] && data.candidates[0].content &&
    data.candidates[0].content.parts && data.candidates[0].content.parts.map((p) => p.text || '').join('\n')) || '';
  if (!text.trim()) { const err = new Error('الذكاء الاصطناعي رجّع رد فاضي، جرّب تاني.'); err.status = 502; throw err; }
  return text.trim();
}

// Uploads the video to Gemini's Files API (resumable protocol) and waits
// until it is ACTIVE. Returns { name, uri, mimeType }.
async function uploadVideoToGemini(env, videoRes, displayName, opts) {
  const mimeType = (videoRes.headers.get('Content-Type') || 'video/mp4').split(';')[0] || 'video/mp4';
  let size = parseInt(videoRes.headers.get('Content-Length') || '0', 10);
  let buffered = null;
  if (!size || size <= BUFFER_VIDEO_BYTES) {
    buffered = await videoRes.arrayBuffer();
    size = buffered.byteLength;
  }
  if (!size) throw Object.assign(new Error('الفيديو فاضي أو مش متاح.'), { status: 422 });
  if (size > MAX_VIDEO_BYTES) throw Object.assign(new Error('الفيديو كبير أوي على التحليل (أكتر من 400MB).'), { status: 413 });

  const startRes = await fetch(`${GEMINI_FILES_BASE}/upload/v1beta/files`, {
    method: 'POST',
    headers: {
      'x-goog-api-key': env.GEMINI_API_KEY,
      'X-Goog-Upload-Protocol': 'resumable',
      'X-Goog-Upload-Command': 'start',
      'X-Goog-Upload-Header-Content-Length': String(size),
      'X-Goog-Upload-Header-Content-Type': mimeType,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ file: { display_name: displayName } }),
  });
  const uploadUrl = startRes.headers.get('x-goog-upload-url');
  if (!startRes.ok || !uploadUrl) {
    throw Object.assign(new Error('تعذّر بدء رفع الفيديو لـ Gemini: ' + (await startRes.text())), { status: 502 });
  }

  let body;
  if (buffered) {
    body = buffered;
  } else {
    const { readable, writable } = new FixedLengthStream(size);
    videoRes.body.pipeTo(writable); // runs concurrently with the upload fetch
    body = readable;
  }
  const upRes = await fetch(uploadUrl, {
    method: 'POST',
    headers: {
      'Content-Length': String(size),
      'X-Goog-Upload-Offset': '0',
      'X-Goog-Upload-Command': 'upload, finalize',
    },
    body,
  });
  if (!upRes.ok) throw Object.assign(new Error('فشل رفع الفيديو لـ Gemini: ' + (await upRes.text())), { status: 502 });
  const upData = await upRes.json();
  let file = upData.file;
  if (!file || !file.name) throw Object.assign(new Error('رد غير متوقع من رفع الفيديو.'), { status: 502 });

  if (opts && opts.wait === false) {
    return { name: file.name, uri: file.uri, mimeType: file.mimeType || mimeType, state: file.state };
  }

  // wait for processing
  const deadline = Date.now() + 120000;
  while (file.state === 'PROCESSING' && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 3000));
    const st = await fetch(`${GEMINI_FILES_BASE}/v1beta/${file.name}`, { headers: { 'x-goog-api-key': env.GEMINI_API_KEY } });
    if (st.ok) file = await st.json();
  }
  if (file.state !== 'ACTIVE') throw Object.assign(new Error('Gemini لسه مخلصش معالجة الفيديو، جرّب تاني بعد شوية.'), { status: 504 });
  return { name: file.name, uri: file.uri, mimeType: file.mimeType || mimeType };
}

async function deleteGeminiFile(env, name) {
  try {
    await fetch(`${GEMINI_FILES_BASE}/v1beta/${name}`, { method: 'DELETE', headers: { 'x-goog-api-key': env.GEMINI_API_KEY } });
  } catch (e) { /* best effort - files auto-expire after 48h anyway */ }
}

const VIDEO_SCRIPT_RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    title: { type: 'STRING' },
    language: { type: 'STRING' },
    brain: {
      type: 'OBJECT',
      properties: {
        topic: { type: 'STRING' },
        sections: { type: 'ARRAY', items: { type: 'STRING' } },
        definitions: { type: 'ARRAY', items: { type: 'STRING' } },
        lists: { type: 'ARRAY', items: { type: 'STRING' } },
        formulas: { type: 'ARRAY', items: { type: 'STRING' } },
        examples: { type: 'ARRAY', items: { type: 'STRING' } },
        tables: { type: 'ARRAY', items: { type: 'STRING' } },
        warnings: { type: 'ARRAY', items: { type: 'STRING' } }
      }
    },
    scenes: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          title: { type: 'STRING' },
          on_screen: { type: 'STRING' },
          bullets: { type: 'ARRAY', items: { type: 'STRING' } },
          narration: { type: 'STRING' },
          duration: { type: 'NUMBER' },
          kind: { type: 'STRING' },
          example: { type: 'BOOLEAN' },
          source_anchor: { type: 'STRING' },
          source_facts: { type: 'ARRAY', items: { type: 'STRING' } },
          source_image_index: { type: 'NUMBER' },
          visual_type: { type: 'STRING' },
          visual_focus: { type: 'STRING' },
          emphasis: { type: 'ARRAY', items: { type: 'STRING' } },
          draw_steps: { type: 'ARRAY', items: { type: 'STRING' } },
          solution_steps: {
            type: 'ARRAY',
            items: { type: 'OBJECT', properties: { step: { type: 'STRING' }, why: { type: 'STRING' }, calculation: { type: 'STRING' } } }
          },
          diagram: {
            type: 'OBJECT',
            properties: {
              center: { type: 'STRING' },
              nodes: { type: 'ARRAY', items: { type: 'STRING' } },
              relations: { type: 'ARRAY', items: { type: 'STRING' } }
            }
          },
          table: {
            type: 'OBJECT',
            properties: {
              headers: { type: 'ARRAY', items: { type: 'STRING' } },
              rows: { type: 'ARRAY', items: { type: 'ARRAY', items: { type: 'STRING' } } }
            }
          }
        },
        required: ['title', 'on_screen', 'bullets', 'narration', 'duration', 'kind', 'example']
      }
    }
  },
  required: ['title', 'language', 'scenes']
};

function extractJsonObject(text) {
  const cleaned = String(text || '').replace(/```json|```/gi, '').trim();
  try { return JSON.parse(cleaned); } catch (_) {}
  // If Gemini wrapped the JSON in a sentence, find the largest balanced object.
  let start = -1, depth = 0, inString = false, escaped = false, candidate = '';
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '{') { if (depth === 0) start = i; depth++; }
    else if (ch === '}' && depth > 0) { depth--; if (depth === 0 && start >= 0) { candidate = cleaned.slice(start, i + 1); try { return JSON.parse(candidate); } catch (_) { start = -1; candidate = ''; } } }
  }
  const err = new Error('رد الذكاء الاصطناعي جه بشكل غير مفهوم، جرّب تاني.');
  err.status = 502;
  err.rawPreview = cleaned.slice(0, 1200);
  throw err;
}

async function callGemini(env, parts, extraConfig) {
  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
  const config = Object.assign({ responseMimeType: 'application/json' }, extraConfig || {});
  const apiResponse = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
    body: JSON.stringify({
      contents: [{ role: 'user', parts }],
      generationConfig: config,
    }),
  });

  if (!apiResponse.ok) {
    const errText = await apiResponse.text();
    const err = new Error('Gemini API error: ' + errText);
    err.status = apiResponse.status;
    throw err;
  }

  const data = await apiResponse.json();

  // A genuine Gemini safety block (as opposed to a quota/network/parse
  // problem) - the ask handler is the only place that treats this as abuse.
  const blockReason = data.promptFeedback && data.promptFeedback.blockReason;
  const finishReason = data.candidates && data.candidates[0] && data.candidates[0].finishReason;
  if (blockReason || finishReason === 'SAFETY' || finishReason === 'PROHIBITED_CONTENT' || finishReason === 'BLOCKLIST') {
    const err = new Error('Gemini blocked this content (' + (blockReason || finishReason) + ')');
    err.safetyBlocked = true;
    throw err;
  }

  const rawText = (data.candidates && data.candidates[0] &&
    data.candidates[0].content && data.candidates[0].content.parts &&
    data.candidates[0].content.parts.map((p) => p.text || '').join('\n')) || '';
  return extractJsonObject(rawText);
}


async function sha1Hex(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function uploadGeneratedVideoToCloudinary(env, request) {
  const account = await verifyRealUser(request, env);
  if (!account) return jsonResponse({ error: 'unauthorized' }, 401);
  if (!env.CLOUDINARY_CLOUD_NAME || !env.CLOUDINARY_API_KEY || !env.CLOUDINARY_API_SECRET) {
    return jsonResponse({ error: 'CLOUDINARY generated-video secrets are not configured on the Worker.' }, 503);
  }
  const form = await request.formData();
  const file = form.get('file');
  const filename = String(form.get('filename') || 'ai-video.webm').slice(0, 180);
  if (!(file instanceof File)) return jsonResponse({ error: 'file is required' }, 400);
  if (file.size > 80 * 1024 * 1024) return jsonResponse({ error: 'الفيديو أكبر من الحد المسموح (80MB).' }, 413);
  const timestamp = Math.floor(Date.now() / 1000);
  const safeId = ('justm_ai_' + account.uid + '_' + timestamp).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 120);
  const folder = 'justm_ai_videos';
  const signatureBase = `folder=${folder}&public_id=${safeId}&timestamp=${timestamp}${env.CLOUDINARY_API_SECRET}`;
  const signature = await sha1Hex(signatureBase);
  const up = new FormData();
  up.append('file', file, filename);
  up.append('api_key', env.CLOUDINARY_API_KEY);
  up.append('timestamp', String(timestamp));
  up.append('folder', folder);
  up.append('public_id', safeId);
  up.append('signature', signature);
  const cloud = await fetch(`https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/video/upload`, { method: 'POST', body: up });
  const data = await cloud.json().catch(() => ({}));
  if (!cloud.ok || !data.secure_url) return jsonResponse({ error: data.error?.message || `Cloudinary upload failed (${cloud.status})` }, 502);
  return jsonResponse({ ok: true, secure_url: data.secure_url, bytes: file.size, filename });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders() });

    if (request.headers.get('X-JustM-Action') === 'generated_video_upload') {
      return uploadGeneratedVideoToCloudinary(env, request);
    }

    let body;
    try { body = await request.json(); }
    catch (e) { return jsonResponse({ error: 'invalid JSON body' }, 400); }

    const mode = body.mode || 'quiz';

    try {
      // ---- score tracking: authenticated course users only ----
      // Never trust a client-supplied student name as the identity. Scores are
      // now keyed by the verified Firebase UID, so one student cannot request
      // another student's history by changing {student: ...}.
      if (mode === 'save_score' || mode === 'get_scores') {
        const account = await verifyRealUser(request, env);
        if (!account) return jsonResponse({ error: 'unauthorized: invalid or missing identity token' }, 401);

        const key = 'scores:' + account.uid;
        if (mode === 'get_scores') {
          const raw = await env.QUIZ_KV.get(key);
          return jsonResponse({ scores: raw ? JSON.parse(raw) : [] });
        }

        const subject = String(body.subject || '').trim().slice(0, 200);
        const lecture = String(body.lecture || '').trim().slice(0, 300);
        const difficulty = ['easy', 'medium', 'hard'].includes(body.difficulty) ? body.difficulty : '';
        const score = Number(body.score);
        const total = Number(body.total);
        if (!Number.isFinite(score) || !Number.isFinite(total) || total <= 0 || score < 0 || score > total) {
          return jsonResponse({ error: 'invalid score' }, 400);
        }

        let existingRaw;
        try { existingRaw = await env.QUIZ_KV.get(key); } catch (e) {
          return jsonResponse({ error: 'score storage unavailable' }, 503);
        }
        let list = [];
        try { list = existingRaw ? JSON.parse(existingRaw) : []; } catch (e) { list = []; }
        if (!Array.isArray(list)) list = [];
        list.push({ subject, lecture, score, total, difficulty, at: Date.now() });
        try {
          await env.QUIZ_KV.put(key, JSON.stringify(list.slice(-100)));
        } catch (e) {
          return jsonResponse({ error: 'score storage unavailable' }, 503);
        }
        return jsonResponse({ ok: true });
      }

      // ---- admin: AI usage log + ban list ----
      const requestIp = request.headers.get('CF-Connecting-IP') || 'unknown';

      const OWNER_ONLY_MODES = ['get_ai_log', 'get_banned', 'ban_user', 'unban_user', 'video_env_check', 'video_start', 'video_poll', 'video_generate', 'course_level_summary'];
      if (OWNER_ONLY_MODES.includes(mode)) {
        // FIX: these four used to run with no check at all. Now the Worker
        // verifies the caller's Firebase ID token itself and requires the
        // "owner" role, instead of trusting whatever the client sends.
        const account = await verifyOwner(request, env);
        if (!account || account.role !== 'owner') {
          return jsonResponse({ error: 'unauthorized' }, 403);
        }
      }

      // ---- owner: ONE course video -> study notes, in 3 short steps so the app
      // can show real progress and no single request has to stay open for minutes:
      //   video_start    : read the video, hand it to Gemini (or return cached notes)
      //   video_poll     : is Gemini done processing the file?
      //   video_generate : Gemini watches it and writes the notes
      // lets the app verify the Service Binding BEFORE it starts analysing dozens of videos
      if (mode === 'video_env_check') {
        return jsonResponse({
          binding: !!(env.COURSES_WORKER && typeof env.COURSES_WORKER.fetch === 'function'),
          binding_type: typeof env.COURSES_WORKER,
          gemini_key: !!env.GEMINI_API_KEY,
          kv: !!env.QUIZ_KV,
        });
      }

      if (mode === 'video_start') {
        const lectureId = String(body.lecture_id || '').trim();
        const videoUrl = String(body.video_url || '').trim();
        const title = String(body.title || 'فيديو').slice(0, 150);
        if (!lectureId || !isAllowedVideoUrl(videoUrl)) return jsonResponse({ error: 'invalid video' }, 400);

        if (env.QUIZ_KV && body.force !== true) {
          const cached = await env.QUIZ_KV.get('vidnotes:' + (await sha256Hex(lectureId)));
          if (cached) return jsonResponse({ cached: true, notes: cached });
        }

        // A Worker can't fetch another Worker's *.workers.dev URL from the same
        // account over the public internet (Cloudflare answers 404 / error 1042),
        // so use a Service Binding named COURSES_WORKER when it is configured.
        let videoRes;
        try {
          videoRes = (env.COURSES_WORKER && typeof env.COURSES_WORKER.fetch === 'function')
            ? await env.COURSES_WORKER.fetch(videoUrl)
            : await fetch(videoUrl);
        } catch (e) {
          return jsonResponse({ error: 'تعذّر الوصول لـ Worker الكورسات: ' + (e && e.message ? e.message : e) }, 502);
        }
        if (!videoRes.ok) {
          let detail = '';
          try { detail = (await videoRes.text()).replace(/\s+/g, ' ').slice(0, 160); } catch (e) { /* ignore */ }
          const hint = (!(env.COURSES_WORKER && typeof env.COURSES_WORKER.fetch === 'function') && videoRes.status === 404)
            ? ' — لازم تضيف Service Binding (مش Variable) اسمه COURSES_WORKER لـ Worker الكورسات.'
            : '';
          return jsonResponse({ error: 'تعذّر قراءة الفيديو (' + videoRes.status + ')' + (detail ? ' [' + detail + ']' : '') + hint }, 502);
        }

        const up = await uploadVideoToGemini(env, videoRes, title, { wait: false });
        return jsonResponse({ cached: false, file_name: up.name, file_uri: up.uri, mime_type: up.mimeType, state: up.state });
      }

      if (mode === 'video_poll') {
        const fileName = String(body.file_name || '');
        if (!/^files\/[A-Za-z0-9_-]+$/.test(fileName)) return jsonResponse({ error: 'invalid file' }, 400);
        const st = await fetch(`${GEMINI_FILES_BASE}/v1beta/${fileName}`, { headers: { 'x-goog-api-key': env.GEMINI_API_KEY } });
        if (!st.ok) return jsonResponse({ error: 'تعذّر قراءة حالة الفيديو عند Gemini (' + st.status + ')' }, 502);
        const f = await st.json();
        return jsonResponse({ state: f.state || 'UNKNOWN' });
      }

      if (mode === 'video_generate') {
        const lectureId = String(body.lecture_id || '').trim();
        const fileName = String(body.file_name || '');
        const fileUri = String(body.file_uri || '');
        const mimeType = String(body.mime_type || 'video/mp4');
        const title = String(body.title || 'فيديو').slice(0, 150);
        if (!lectureId || !/^files\/[A-Za-z0-9_-]+$/.test(fileName) || fileUri.indexOf(GEMINI_FILES_BASE) !== 0) {
          return jsonResponse({ error: 'invalid file' }, 400);
        }
        try {
          const prompt =
            'شاهد الفيديو التعليمي ده كامل (الصوت والصورة وأي نص أو شرائح أو سبورة أو أرقام بتظهر على الشاشة) واكتب ملاحظات مذاكرة مفصّلة ودقيقة عنه. ' +
            'اكتب بنفس لغة الشرح في الفيديو (غالبًا عربي، وسيب المصطلحات الإنجليزية بالإنجليزي). ' +
            'لازم تغطي: كل الأفكار والمفاهيم الأساسية بالترتيب، التعريفات، القواعد والقوانين والمعادلات، الخطوات العملية، الأمثلة اللي اتحلت (بأرقامها)، ونصائح المدرّس أو تنبيهاته. ' +
            'ما تخترعش معلومة مش موجودة في الفيديو. اكتب نص عادي بدون markdown (من غير ** أو #)، وتقدر تستخدم أسطر مرقّمة. ' +
            'ابدأ بسطر: "الموضوع: ..." بعدين الملاحظات.\n\nعنوان الفيديو: ' + title;
          const notes = await callGeminiText(env, [
            { fileData: { mimeType, fileUri } },
            { text: prompt },
          ]);
          if (env.QUIZ_KV) await env.QUIZ_KV.put('vidnotes:' + (await sha256Hex(lectureId)), notes, { expirationTtl: CACHE_TTL_SECONDS });
          return jsonResponse({ notes });
        } finally {
          await deleteGeminiFile(env, fileName);
        }
      }

      // ---- owner: merge every video's notes into ONE level-wide summary ----
      if (mode === 'course_level_summary') {
        const items = Array.isArray(body.notes) ? body.notes : [];
        const courseName = String(body.course_name || 'الكورس').slice(0, 100);
        const courseNumber = Number(body.course_number) || 1;
        const joined = items
          .map((it, i) => '### جزء ' + (i + 1) + '\n' + String(it && it.notes || '').trim())
          .filter((t) => t.length > 20)
          .join('\n\n')
          .slice(0, 400000);
        if (!joined) return jsonResponse({ error: 'notes are required' }, 400);

        const prompt =
          'ده مادة مفصّلة طالعة من كل فيديوهات مستوى كامل في كورس "' + courseName + '" (المستوى ' + courseNumber + '). ' +
          'اكتب ملخص شامل واحد للمستوى كله بحيث الطالب يذاكر منه بدل ما يرجع للفيديوهات. ' +
          'قواعد مهمة: ' +
          '(1) نظّم الملخص حسب الموضوعات والمفاهيم نفسها، مش فيديو فيديو، وما تذكرش "الفيديو الأول/التاني" ولا أرقام الأجزاء. ' +
          '(2) ادمج الأفكار المتكررة في مكان واحد ورتّب الأقسام ترتيب منطقي من الأساسيات للأصعب. ' +
          '(3) خلّي التعريفات والقواعد والقوانين والخطوات والأمثلة المهمة (بأرقامها) موجودة كاملة ودقيقة، ومتخترعش معلومات مش في المادة. ' +
          '(3.5) اكتب نص عادي بدون أي علامات markdown: ممنوع ** أو # أو - في أول السطر. ' +
          '(4) اختم بقسم "نقاط المراجعة السريعة" فيه أهم النقاط في قايمة قصيرة. ' +
          'اكتب بنفس لغة المادة. رد بـ JSON صالح فقط بدون markdown fences، بالشكل: ' +
          '{"title":"...","sections":[{"heading":"...","paragraphs":["..."],"bullets":["..."]}]}. ' +
          'استخدم من 6 لـ 14 قسم حسب حجم المادة، وكل قسم فيه paragraphs أو bullets أو الاتنين.\n\nالمادة:\n\n' + joined;

        // a whole level can produce a long document: raise the output cap so the
        // JSON isn't cut off mid-way, then strip any markdown that slipped in.
        const result = await callGemini(env, [{ text: prompt }], { maxOutputTokens: 60000 });
        const clean = (t) => String(t == null ? '' : t)
          .replace(/\*\*(.+?)\*\*/g, '$1').replace(/\*\*/g, '').replace(/^\s{0,3}#{1,6}\s+/gm, '').replace(/`+/g, '').trim();
        if (result && Array.isArray(result.sections)) {
          result.title = clean(result.title);
          result.sections = result.sections.map((sec) => ({
            heading: clean(sec.heading),
            paragraphs: (sec.paragraphs || []).map(clean).filter(Boolean),
            bullets: (sec.bullets || []).map(clean).filter(Boolean),
          }));
        }
        return jsonResponse(result);
      }

      if (mode === 'get_ai_log') {
        const raw = await env.QUIZ_KV.get('ai_log');
        return jsonResponse({ log: raw ? JSON.parse(raw) : [] });
      }

      if (mode === 'get_banned') {
        const raw = await env.QUIZ_KV.get('banned_users');
        return jsonResponse({ banned: raw ? JSON.parse(raw) : [] });
      }

      if (mode === 'ban_user') {
        const target = (body.target || '').trim();
        if (!target) return jsonResponse({ error: 'target required' }, 400);
        const raw = await env.QUIZ_KV.get('banned_users');
        const list = raw ? JSON.parse(raw) : [];
        if (list.indexOf(target) === -1) list.push(target);
        await env.QUIZ_KV.put('banned_users', JSON.stringify(list));
        return jsonResponse({ ok: true, banned: list });
      }

      if (mode === 'unban_user') {
        const target = (body.target || '').trim();
        const raw = await env.QUIZ_KV.get('banned_users');
        const list = (raw ? JSON.parse(raw) : []).filter((t) => t !== target);
        await env.QUIZ_KV.put('banned_users', JSON.stringify(list));
        return jsonResponse({ ok: true, banned: list });
      }

      // Any mode from here on can call Gemini or reflects AI usage - block banned
      // IPs before doing anything else.
      const bannedRaw = await env.QUIZ_KV.get('banned_users');
      const bannedList = bannedRaw ? JSON.parse(bannedRaw) : [];
      if (bannedList.indexOf(requestIp) !== -1) {
        return jsonResponse({ error: 'ممنوع استخدام الذكاء الاصطناعي من هذا الجهاز — تواصل مع إدارة المنصة لو ده غلط.' }, 403);
      }

      // ---- AI explainer video script ------------------------------
      if (mode === 'video_explain') {
        const text = String(body.text || '').trim().slice(0, 70000);
        const images = Array.isArray(body.images) ? body.images.slice(0, 12) : [];
        const subject = String(body.subject || 'المادة').slice(0, 120);
        const request = String(body.request || '').trim().slice(0, 1200);
        if (!text && !images.length) {
          return jsonResponse({ error: 'محتوى المحاضرة مطلوب' }, 400);
        }
        const effectiveRequest = request || 'اشرح المحاضرة كاملة من البداية للنهاية، مع الحفاظ على ترتيب الأفكار وعدم إسقاط النقاط الأساسية.';

        const prompt =
          'أنت أستاذ جامعي عربي وخبير في تصميم فيديوهات تعليمية. حوّل محتوى الملف المرفق إلى فيديو عربي دقيق ومفيد، والتزم بنوع الشرح المحدد في طلب الطالب. ' +
          'هناك ثلاثة أنماط فقط ويجب تنفيذ النمط المختار حرفيًا: ' +
          '1) النظري / المبسّط: شرح تفصيلي يغطي محتوى الملف بالترتيب، ويشمل كل التعريفات والقوانين والنظريات والمبادئ والعلاقات والاستثناءات والملاحظات المهمة الواردة في المصدر. لا تختزل التعريفات ولا تتجاوز قانونًا أو نظرية مذكورة. إذا احتوى الملف على جزء عملي أو مسألة، اشرح معناها وخطواتها أيضًا. ' +
          '2) المكثّف: مراجعة سريعة ومركزة للنظري، مع أولوية واضحة للمسائل والأرقام والقوانين والتعويض في القوانين وخطوات الحل والأمثلة التطبيقية. اشرح خطوات الحساب ولا تذكر الناتج وحده، ولا تخترع أرقامًا أو قواعد من خارج المصدر؛ إذا أنشأت مثالًا توضيحيًا فصرّح أنه مثال توضيحي. ' +
          '3) الشامل: فيديو مطوّل يجمع النمطين السابقين؛ يغطي النظري بالتفصيل ثم يشرح الأجزاء العملية والمسائل والأرقام والأمثلة خطوة بخطوة، مع انتقالات واضحة وخلاصة نهائية. لا تحوّله إلى ملخص قصير. ' +
          'اعتمد على النص والصور المرفقة فقط للمعلومات الأكاديمية. لا تخترع معلومة ولا تغيّر مصطلحات الملف. إذا كان شيء غير مقروء أو غير موجود فاذكر أن المصدر لا يوضحه بدل التخمين. ' +
          'ممنوع تمامًا تحويل المحتوى إلى كلام عام مثل "ملخص سريع" أو "من أهم النقاط" بدل شرح المادة نفسها. التعريفات يجب نقل معناها كاملًا، ومميزات/خصائص أي مفهوم يجب ذكرها نقطة نقطة كما وردت في المصدر، ولا تختزل قائمة من عدة نقاط إلى جملة واحدة. ' +
          'لا تكتب "مثال عملي" أو example=true إلا إذا كان المصدر نفسه يحتوي فعلًا على مثال أو مسألة أو أرقام أو حالة تطبيقية واضحة. إذا لم يوجد مثال في المصدر، example=false ولا تنشئ مثالًا من عندك. وبالمثل لا تدّعِ وجود جدول إذا لم يوجد جدول. إذا وجد جدول أو مقارنة أو بيانات رقمية في المصدر، انقل البيانات الأساسية إليه في حقل table بدل وصفه بكلام عام. ' +
          'اكتب بالعربية الواضحة، ويمكن إبقاء المصطلح الإنجليزي بين قوسين عند الحاجة. حافظ على ترتيب المحاضرة. ' +
          'أنشئ عددًا كافيًا من المشاهد لتغطية المادة دون حشو: من 10 إلى 30 مشهدًا حسب حجم المحتوى. لا تضع أكثر من مفهوم مستقل في مشهد واحد إذا كان ذلك سيؤدي لاختصار التعريف أو إسقاط نقاط. كل مشهد يحتوي عنوانًا، ونقاطًا واضحة على الشاشة، وسردًا عربيًا كاملًا يصلح للصوت، ومدة تقديرية من 6 إلى 16 ثانية. اجعل السرد هو الشرح الفعلي وليس مجرد قراءة العناوين. ' +
          'في أي مشهد عملي يحتوي أرقامًا أو جدولًا أو مسألة، يجب ربطه بصورة صفحة المصدر عبر source_image_index متى كانت الصفحة ضمن الصور المرفقة. لا تضع أي رقم في bullets أو narration إلا إذا كان ظاهرًا في النص أو الصورة. ' + 'في المسائل اكتب المعطيات والقانون والتعويض والحساب والنتيجة والتفسير إن كانت متاحة في المصدر، وبنفس الأرقام. لا تسقط الوحدات أو الإشارات أو الأرقام. في التعريفات اذكر التعريف كاملًا، وفي التصنيفات اذكر عناصر التصنيف، وفي المميزات اذكر كل ميزة مهمة وردت في المصدر. ابدأ بمقدمة قصيرة وانتهِ بخلاصة حقيقية للمادة. ' +
          'قبل بناء المشاهد نفّذ AI Brain داخليًا: صنّف المادة إلى تعريفات، قوائم/مميزات، قوانين وصيغ، أمثلة/مسائل، جداول/مقارنات، وأفكار نظرية. لا تُنشئ أي فئة إذا لم توجد في المصدر. أعد هذا التحليل أيضًا في حقل brain. ' +
          'مهم جدًا: لا تكتفِ بكتابة نص على الشاشة. صمّم كل مشهد كشرح بصري تفاعلي بأسلوب دفتر/سبورة ذكية مستوحى من فكرة Notebook التعليمية، لكن بهوية JustM وتصميم مستقل. لكل مشهد اختر visual_type واحدًا من: card أو steps أو flow أو compare أو formula أو worked_example أو concept_map أو timeline أو table أو source_image أو focus. اختر النوع بناءً على طبيعة المعلومة، وليس عشوائيًا. استخدم card للتعريفات، steps للخطوات، flow للعلاقات، compare للمقارنات، formula للقوانين، worked_example للمسائل، concept_map للمفاهيم المترابطة، timeline للتسلسل الزمني، table للجداول الحقيقية، source_image عندما تكون صورة المصدر هي أفضل وسيلة، وfocus عندما تكون هناك فكرة واحدة يجب إبرازها. لا تستخدم نفس النوع لكل المشاهد المتتالية إذا كان هناك بديل أفضل. ' +
          'لكل مشهد أضف visual_focus كجملة قصيرة تحدد بالضبط ما يجب أن تركز عليه عين الطالب في هذه اللحظة. وأضف emphasis ككلمات أو عبارات قصيرة مهمة من المصدر، وdraw_steps كمراحل قصيرة للرسم/البناء البصري إذا كان visual_type يحتاج بناءً تدريجيًا. يمكن إضافة diagram بالشكل {center,nodes:[...],relations:[...]} فقط عندما توجد علاقة مفاهيم حقيقية. لا تخترع علاقات غير موجودة في المصدر. الهدف أن تظهر المعلومة تدريجيًا مع الصوت: لا تعرض كل شيء من البداية. ' +
          'في المشاهد العملية أو المسائل استخدم solution_steps عند توفر حل واضح، بالشكل [{step,why,calculation}]، بحيث يظهر الحل مرحلة مرحلة ويعرف الطالب لماذا انتقلنا لكل خطوة. لا تملأ هذا الحقل في المشاهد النظرية العادية. ' +
          'لكل مشهد أضف source_anchor كعبارة قصيرة مأخوذة من المصدر تساعد على مراجعة أمانة المشهد، وأضف source_facts كأهم حقائق المصدر التي يعتمد عليها المشهد. إذا كان المشهد عمليًا أو يحتوي جدولًا/مسألة/أرقامًا وكان قائمًا على إحدى صور الصفحات المرفقة، أضف source_image_index كرقم الصورة من 0 إلى 11. لا تستخدم source_image_index إذا لم تكن الصورة مفيدة. في المشاهد العملية اعتمد على الصورة والبيانات الأصلية ولا تخترع أرقامًا. لا تستخدم source_anchor أو source_facts لاختراع معلومات جديدة. ' +
          'بعد إنشاء المشاهد راجعها مقابل المصدر: التعريفات والقوائم والأرقام والقوانين يجب ألا تُختصر بطريقة تغيّر المعنى. إذا لم تجد سندًا واضحًا لمعلومة، احذفها. ' +
          'كل مشهد يجب أن يحتوي kind من القيم: theory أو definition أو list أو formula أو example أو table أو summary. حقل bullets يحتوي 2 إلى 6 نقاط دقيقة من المصدر. حقل table اختياري، وشكله {headers:[...],rows:[[...],[...]]}، ولا تستخدمه إلا عند وجود جدول/مقارنة فعلية في المصدر. ' +
          'ممنوع markdown داخل الحقول. أرجع JSON صالح فقط بهذا الشكل: ' +
          '{"title":"...","language":"ar","brain":{"topic":"...","sections":["..."],"definitions":[],"lists":[],"formulas":[],"examples":[],"tables":[],"warnings":[]},"scenes":[{"title":"...","on_screen":"...","bullets":["..."],"narration":"...","duration":8,"kind":"theory","visual_type":"card","visual_focus":"...","emphasis":["..."],"draw_steps":["..."],"solution_steps":[{"step":"...","why":"...","calculation":"..."}],"diagram":{"center":"...","nodes":["..."],"relations":["..."]},"example":false,"source_anchor":"...","source_facts":["..."],"table":{"headers":["..."],"rows":[["..."]]}}]}. ' +
          'الموضوع: ' + subject + '\n' +
          'النمط وطلب الطالب: ' + effectiveRequest + '\n\n' +
          'مادة المحاضرة كما استُخرجت من الملف:\n' + text;

        const parts = [{ text: prompt }];
        for (const img of images) {
          if (img && img.mimeType && img.data) {
            parts.push({ inlineData: { mimeType: String(img.mimeType), data: String(img.data) } });
          }
        }

        let result;
        try {
          result = await callGemini(env, parts, {
            maxOutputTokens: 24000,
            responseMimeType: 'application/json',
            responseSchema: VIDEO_SCRIPT_RESPONSE_SCHEMA,
            temperature: 0.2
          });
        } catch (firstErr) {
          // A second, compact retry prevents a transient/truncated JSON response
          // from turning into a useless 502. The retry explicitly asks for fewer,
          // denser scenes while preserving all source facts.
          if (firstErr && firstErr.status === 502) {
            const retryParts = [{ text: prompt + '\n\nإعادة محاولة تقنية: أخرج JSON صالحًا بالكامل. لا تكتب أي نص خارج JSON. اجعل عدد المشاهد 8-18 فقط، واجعل كل مشهد مركزًا لكن لا تحذف التعريفات أو القوائم أو القوانين أو خطوات الحل. إذا لم توجد أمثلة أو جداول في المصدر فلا تضفها.' }];
            for (const img of images) {
              if (img && img.mimeType && img.data) retryParts.push({ inlineData: { mimeType: String(img.mimeType), data: String(img.data) } });
            }
            result = await callGemini(env, retryParts, {
              maxOutputTokens: 24000,
              responseMimeType: 'application/json',
              responseSchema: VIDEO_SCRIPT_RESPONSE_SCHEMA,
              temperature: 0.1
            });
          } else {
            throw firstErr;
          }
        }
        const clean = (v) => String(v == null ? '' : v).replace(/[*#`]/g, '').trim();
        result = result && typeof result === 'object' ? result : {};
        result.title = clean(result.title || 'شرح بالفيديو');
        result.language = 'ar';
        const rawBrain = (result.brain && typeof result.brain === 'object') ? result.brain : {};
        result.brain = {
          topic: clean(rawBrain.topic || subject),
          sections: Array.isArray(rawBrain.sections) ? rawBrain.sections.map(clean).filter(Boolean).slice(0,30) : [],
          definitions: Array.isArray(rawBrain.definitions) ? rawBrain.definitions.map(clean).filter(Boolean).slice(0,30) : [],
          lists: Array.isArray(rawBrain.lists) ? rawBrain.lists.map(clean).filter(Boolean).slice(0,30) : [],
          formulas: Array.isArray(rawBrain.formulas) ? rawBrain.formulas.map(clean).filter(Boolean).slice(0,30) : [],
          examples: Array.isArray(rawBrain.examples) ? rawBrain.examples.map(clean).filter(Boolean).slice(0,30) : [],
          tables: Array.isArray(rawBrain.tables) ? rawBrain.tables.map(clean).filter(Boolean).slice(0,30) : [],
          warnings: Array.isArray(rawBrain.warnings) ? rawBrain.warnings.map(clean).filter(Boolean).slice(0,30) : []
        };

        let rawScenes = Array.isArray(result.scenes) ? result.scenes : [];
        if (!rawScenes.length) {
          const chunks = String(text || '').split(/(?<=[.!؟:])\s+/).filter(Boolean);
          const groups = [];
          const step = Math.max(1, Math.ceil(chunks.length / 6));
          for (let i = 0; i < chunks.length; i += step) {
            groups.push(chunks.slice(i, i + step).join(' '));
          }

          if (groups.length) {
            rawScenes = groups.slice(0, 8).map((chunk, i) => ({
              title: i === 0 ? 'مقدمة' : ('النقطة ' + (i + 1)),
              on_screen: chunk.slice(0, 180),
              narration: chunk,
              duration: 8,
              example: false
            }));
          } else {
            return jsonResponse({
              error: 'VIDEO_SCRIPT_EMPTY',
              message: 'الـWorker استلم محتوى بدون نص قابل للتحويل إلى سيناريو.',
              diagnostics: {
                geminiResultType: typeof result,
                geminiKeys: result && typeof result === 'object' ? Object.keys(result).slice(0, 30) : [],
                scenesType: result && result.scenes != null ? typeof result.scenes : 'missing',
                scenesCount: Array.isArray(result?.scenes) ? result.scenes.length : 0,
                lectureTextLength: String(text || '').length,
                imageCount: images.length,
                responsePreview: JSON.stringify(result ?? null).slice(0, 1000)
              }
            }, 502);
          }
        }

        result.scenes = rawScenes.slice(0, 24).map((x, i) => {
          x = x && typeof x === 'object' ? x : {};
          const title = clean(x.title || ('النقطة ' + (i + 1)));
          const onScreen = clean(x.on_screen || x.title || x.explanation || title);
          const narration = clean(x.narration || x.explanation || x.voiceover || x.script || onScreen || title);
          const bullets = Array.isArray(x.bullets) ? x.bullets.map(clean).filter(Boolean).slice(0, 6) : [];
          const sourceAnchor = clean(x.source_anchor || '');
          const sourceFacts = Array.isArray(x.source_facts) ? x.source_facts.map(clean).filter(Boolean).slice(0,8) : [];
          const kind = ['theory','definition','list','formula','example','table','summary'].includes(String(x.kind)) ? String(x.kind) : 'theory';
          const allowedVisuals = ['card','steps','flow','compare','formula','worked_example','concept_map','timeline','table','source_image','focus'];
          const visualType = allowedVisuals.includes(String(x.visual_type)) ? String(x.visual_type) : (kind === 'definition' ? 'card' : kind === 'formula' ? 'formula' : kind === 'table' ? 'table' : kind === 'example' ? 'worked_example' : kind === 'list' ? 'steps' : 'focus');
          const visualFocus = clean(x.visual_focus || x.title || '');
          const emphasis = Array.isArray(x.emphasis) ? x.emphasis.map(clean).filter(Boolean).slice(0,8) : [];
          const drawSteps = Array.isArray(x.draw_steps) ? x.draw_steps.map(clean).filter(Boolean).slice(0,8) : [];
          const solutionSteps = Array.isArray(x.solution_steps) ? x.solution_steps.slice(0,8).map((z) => ({ step: clean(z?.step || ''), why: clean(z?.why || ''), calculation: clean(z?.calculation || '') })).filter((z) => z.step || z.why || z.calculation) : [];
          let diagram = null;
          if (x.diagram && typeof x.diagram === 'object') {
            const center = clean(x.diagram.center || '');
            const nodes = Array.isArray(x.diagram.nodes) ? x.diagram.nodes.map(clean).filter(Boolean).slice(0,8) : [];
            const relations = Array.isArray(x.diagram.relations) ? x.diagram.relations.map(clean).filter(Boolean).slice(0,8) : [];
            if (center || nodes.length) diagram = { center, nodes, relations };
          }
          let table = null;
          if (x.table && typeof x.table === 'object' && Array.isArray(x.table.headers) && Array.isArray(x.table.rows)) {
            table = {
              headers: x.table.headers.map(clean).filter(Boolean).slice(0, 4),
              rows: x.table.rows.slice(0, 6).map(r => Array.isArray(r) ? r.map(clean).slice(0, 4) : []).filter(r => r.length)
            };
            if (!table.headers.length || !table.rows.length) table = null;
          }
          return {
            title,
            on_screen: onScreen,
            bullets,
            narration,
            duration: Math.max(5, Math.min(16, Number(x.duration) || 8)),
            kind,
            visual_type: visualType,
            ...(visualFocus ? { visual_focus: visualFocus } : {}),
            ...(emphasis.length ? { emphasis } : {}),
            ...(drawSteps.length ? { draw_steps: drawSteps } : {}),
            ...(solutionSteps.length ? { solution_steps: solutionSteps } : {}),
            ...(diagram ? { diagram } : {}),
            example: !!x.example,
            ...(sourceAnchor ? { source_anchor: sourceAnchor } : {}),
            ...(sourceFacts.length ? { source_facts: sourceFacts } : {}),
            ...(Number.isFinite(Number(x.source_image_index)) ? { source_image_index: Math.max(0, Math.min(images.length - 1, Number(x.source_image_index))) } : {}),
            ...(table ? { table } : {})
          };
        }).filter(x => x.narration);

        if (!result.scenes.length) {
          return jsonResponse({
            error: 'VIDEO_NARRATION_EMPTY',
            message: 'Gemini رجّع مشاهد، لكن لم يوجد نص شرح قابل للاستخدام.',
            diagnostics: {
              sceneCount: rawScenes.length,
              firstSceneKeys: rawScenes[0] && typeof rawScenes[0] === 'object' ? Object.keys(rawScenes[0]).slice(0, 30) : [],
              lectureTextLength: String(text || '').length,
              imageCount: images.length
            }
          }, 502);
        }
        return jsonResponse(result);
      }

      // ---- AI video narration audio: real Gemini TTS WAV -----------------
      // Generates one Arabic WAV from the final narration. The browser then
      // combines this audio track with the visual canvas recording.
      if (mode === 'video_tts') {
        const narration = String(body.narration || '').trim().slice(0, 14000);
        const voice = String(body.voice || 'Kore').trim().slice(0, 40);
        const style = String(body.style || 'clear, warm, patient university teacher').trim().slice(0, 300);
        if (!narration) return jsonResponse({ error: 'نص الشرح الصوتي مطلوب' }, 400);
        if (!env.GEMINI_API_KEY) return jsonResponse({ error: 'GEMINI_API_KEY غير مضبوط في Worker' }, 503);

        const ttsUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash-tts:generateContent';
        const ttsRes = await fetch(ttsUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-goog-api-key': env.GEMINI_API_KEY
          },
          body: JSON.stringify({
            contents: [{
              role: 'user',
              parts: [{
                text: narration,
                speech_metadata: { style }
              }]
            }],
            generationConfig: {
              responseModalities: ['AUDIO'],
              speechConfig: {
                voiceConfig: { voice }
              }
            }
          })
        });

        if (!ttsRes.ok) {
          const detail = (await ttsRes.text()).slice(0, 800);
          return jsonResponse({ error: 'تعذر إنشاء الصوت العربي' + (detail ? ': ' + detail : '') }, 502);
        }

        const ttsData = await ttsRes.json();
        const part = ttsData?.candidates?.[0]?.content?.parts?.find(p => p?.inlineData?.data);
        const audioBase64 = part?.inlineData?.data;
        if (!audioBase64) return jsonResponse({ error: 'Gemini لم يُرجع ملفًا صوتيًا صالحًا.' }, 502);

        return jsonResponse({
          mimeType: 'audio/wav',
          sampleRate: 24000,
          audioBase64,
          voice
        });
      }

      // ---- compose_document: turn a student's raw notes into a full,
      // organized lecture (title + sections), used to export a PDF/Word file ----
      if (mode === 'compose_document') {
        const notes = (body.notes || '').trim();
        const composeImages = Array.isArray(body.images) ? body.images.slice(0, 15) : [];
        if (!notes && !composeImages.length) return jsonResponse({ error: 'notes are required' }, 400);
        const subject = body.subject || 'المادة';
        const requestedTitle = (body.title || '').trim();
        const useAiKnowledge = body.use_ai_knowledge === true;
        // raised from 20000: the app now sends full lecture text inside `notes`
        const trimmedNotes = notes.slice(0, 45000);

        let cacheKey = null;
        if (env.QUIZ_KV) {
          const fingerprint = trimmedNotes + '|compose_document|' + subject + '|' + requestedTitle + '|' + (useAiKnowledge ? 'ai' : 'noai') +
            '|' + composeImages.map((i) => (i.data || '').slice(0, 200)).join(',');
          cacheKey = 'cache:' + (await sha256Hex(fingerprint));
          const cached = await env.QUIZ_KV.get(cacheKey);
          if (cached) return jsonResponse(JSON.parse(cached));
        }

        const ip = requestIp;
        const limitMsg = await checkRateLimit(env, ip);
        if (limitMsg) return jsonResponse({ error: limitMsg }, 429);

        const instructions =
          "You are a university teaching assistant turning the given material (lecture text and/or a student's rough notes) into a clean, well-organized lecture document. " +
          'Expand each point into clear explanatory text (do not just repeat it as-is). ' +
          'If a [تعليمات] block is present at the start of the input, follow it exactly. ' +
          'Content that comes from the lecture material must stay accurate to it and never contradict it. ' +
          (useAiKnowledge
            ? 'You ARE allowed and expected to add extra accurate explanations, examples and context from your own knowledge, but put every such addition in its OWN separate section whose heading starts with "إضافة:" so it is clearly distinguishable from the lecture content. Do not mix added material into the lecture sections. '
            : 'Do not add facts beyond the given material. ') +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
          'JSON shape: {"title":"...","sections":[{"heading":"...","paragraphs":["...","..."],"bullets":["...","..."]}]}. ' +
          'Each section should use paragraphs or bullets or both, whichever fits the content best. Aim for 4 to 10 sections depending on how much material there is. ' +
          "Write in Arabic if the material is in Arabic, otherwise match the material's language." +
          (requestedTitle
            ? ` Use this as the document title, lightly polished if needed: "${requestedTitle}".`
            : ' Come up with a clear, specific title yourself.') +
          `\n\nSubject: ${subject}\nMaterial:\n\n${trimmedNotes}` +
          (composeImages.length ? '\n\n(Some lectures are scanned - read their text from the attached page images.)' : '');

        const composeParts = [{ text: instructions }];
        for (const img of composeImages) {
          if (img && img.data) composeParts.push({ inlineData: { mimeType: img.mimeType || 'image/jpeg', data: img.data } });
        }
        const result = await callGemini(env, composeParts);

        if (cacheKey && env.QUIZ_KV) {
          await env.QUIZ_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL_SECONDS });
        }

        return jsonResponse(result);
      }

      // ---- AI-backed modes below ----
      const lectureText = (body.text || '').trim();
      const images = Array.isArray(body.images) ? body.images.slice(0, 25) : [];
      const subject = body.subject || 'المادة';
      const count = Math.min(Math.max(parseInt(body.count) || 10, 1), 25);
      const difficulty = ['easy', 'medium', 'hard'].includes(body.difficulty) ? body.difficulty : 'medium';
      const question = (body.question || '').trim();

      if (!lectureText && !images.length) {
        if (mode === 'ask') {
          return jsonResponse({ error: 'تعذّر قراءة محتوى المحاضرة. أعد فتح المحاضرة أو انتظر اكتمال تحميل الملف ثم جرّب سؤال AI مرة أخرى.' }, 400);
        }
        return jsonResponse({ error: 'محتوى المحاضرة أو صور الصفحات مطلوبة' }, 400);
      }

      const maxChars = mode === 'summary' ? 90000 : (mode === 'ask' ? 150000 : 40000);
      const trimmedText = lectureText.slice(0, maxChars);

      // Cache key: based on content + mode + params. Skip caching for 'ask' (unique per question).
      let cacheKey = null;
      if (mode !== 'ask' && env.QUIZ_KV) {
        const fingerprint = (trimmedText || '') + '|' + images.map((i) => (i.data || '').slice(0, 200)).join(',') +
          '|' + mode + '|' + difficulty + '|' + count + '|' + subject + '|pv:' + (PROMPT_VERSIONS[mode] || '1');
        cacheKey = 'cache:' + (await sha256Hex(fingerprint));
        const cached = await env.QUIZ_KV.get(cacheKey);
        if (cached) return jsonResponse(JSON.parse(cached));
      }

      // Only requests that actually need a fresh Gemini call count against the
      // per-student rate limit — cached results above are free.
      const ip = requestIp;
      const limitMsg = await checkRateLimit(env, ip);
      if (limitMsg) return jsonResponse({ error: limitMsg }, 429);

      const difficultyNote = {
        easy: 'Keep questions at an easy, definition/recall level — direct facts stated in the material.',
        medium: 'Keep questions at a medium level — require understanding and applying a concept, not just recall.',
        hard: 'Keep questions hard — require analysis, comparing concepts, or multi-step reasoning across the material.',
      }[difficulty];

      let instructions;
      if (mode === 'summary') {
        instructions =
          'You are summarizing university lecture material for a student to revise from. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
          'JSON shape: {"overview":"2-3 sentence overview","key_points":["point 1", ...],"terms":[{"term":"...","meaning":"..."}]}. ' +
          'Write in Arabic if the content is in Arabic, otherwise match the source language. Be concrete, not generic.\n\n' +
          `Subject: ${subject}\nSummarize the following lecture content` +
          (images.length ? ' (read the text in the attached scanned pages):' : `:\n\n${trimmedText}`);
      } else if (mode === 'flashcards') {
        instructions =
          'You are creating spaced-repetition flashcards from university lecture material. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
          'JSON shape: {"cards":[{"front":"short question or term","back":"concise answer/definition"}]}. ' +
          'Write in Arabic if the content is in Arabic, otherwise match the source language. Keep each card short and focused on ONE fact.\n\n' +
          `Subject: ${subject}\nGenerate exactly ${count} flashcards from this lecture content` +
          (images.length ? ' (read the text in the attached scanned pages):' : `:\n\n${trimmedText}`);
      } else if (mode === 'video_script') {
        instructions =
          'You are an expert university YouTube lecturer creating a FULL, long-form teaching video from the supplied lecture. This is NOT a summary, revision card, or short recap. ' +
          'Teach the student as if they are watching a high-quality YouTube lesson from beginning to end. Preserve the lecture content and explain it deeply, with natural teacher narration. Do not compress away details just to make the video shorter. ' +
          'Cover ALL theory in the source: definitions, objectives, characteristics, classifications, rules, formulas, steps, notes, conditions, exceptions, tables, comparisons, and important wording. Keep the order logical and faithful to the lecture. ' +
          'PART 1 - theory: build enough scenes to actually teach every concept. Each scene should explain the idea in narration, not merely display bullets. ' +
          'PART 2 - practical (MANDATORY whenever the lecture contains solved examples, exercises, problems, calculations, journal entries, tables of numbers, or case studies): cover EVERY practical item in the order it appears. Never skip, merge, or replace a source problem with a generic summary. ' +
          'For EVERY source practical item, create a dedicated source-problem scene. First show the same problem/data from the lecture, then explain the solution step by step exactly as the source presents it. The narration must explain WHY each step is done, what rule is being used, and how the numbers lead to the result, like a teacher writing on a board. Keep REAL numbers, formulas, account names, dates, and final answers exactly as found in the lecture. ' +
          'After each source problem, create a SECOND dedicated scene of kind "similar_example" containing a NEW but closely related practice example created by you using the SAME method. It must be clearly labeled "مثال مشابه للتدريب — من إنشاء AI" so the student never confuses it with the lecture source. Give the new example concrete numbers and a complete step-by-step solution with all intermediate calculations and the final answer. Do not claim the new example came from the lecture. ' +
          'If the lecture has no practical part, do NOT invent a practical problem merely to fill space. ' +
          'Do NOT add a final summary/wrap-up slide. The goal is teaching, not summarizing. ' +
          'Use as many scenes as necessary; there is NO artificial 8-16 scene limit. A long lecture may need 20, 30, 40 or more scenes. Never shorten the lecture just to fit a target count. ' +
          'For theory scenes: "title" is a clear heading, "bullets" are useful on-screen teaching points, and "narration" is a substantial spoken explanation (normally 4-8 full sentences, and longer when the concept requires it). Do not simply read the bullets. ' +
          'For practical source scenes use kind "example", "table", or "formula" as appropriate and include source_image_index whenever a source page image contains the practical material. For AI-created practice use kind "similar_example" and source_image_index should be omitted. ' +
          'Each practical scene should include enough bullets to show data, each solution step, the reason/rule, and final result. Use a field "solution_steps" when useful: [{"step":"...","why":"...","calculation":"..."}]. For similar_example also include "generated_example":true. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
          'JSON shape: {"slides":[{"kind":"theory|example|table|formula|similar_example","title":"...","bullets":["..."],"narration":"...","solution_steps":[{"step":"...","why":"...","calculation":"..."}],"generated_example":false,"source_image_index":0}]}. ' +
          'Write in Arabic if the content is in Arabic, otherwise match the source language.\n\n' +
          `Subject: ${subject}\nTurn this lecture content into the FULL teaching video script` +
          (images.length ? ' (read the text in the attached scanned pages and use the actual page visuals for practical scenes):' : `:\n\n${trimmedText}`);
      } else if (mode === 'ask') {
        if (!question) return jsonResponse({ error: 'question is required for ask mode' }, 400);
        const dual = body.dual === true;
        const safety =
          'SAFETY CHECK FIRST: if the student\'s message contains insults, profanity, harassment, or abuse (directed at you, the app, staff, or anyone else), ' +
          'set "flagged" to true and leave all answer fields as empty strings — do not engage with or reference the abusive content at all. Otherwise set "flagged" to false. ';
        if (dual) {
          instructions =
            'You are a patient, knowledgeable private tutor answering a student\'s question about their lecture. ' +
            'IMPORTANT about the lecture content: it was extracted automatically from a PDF, so the text may be out of order, split into fragments, have Arabic words broken or reversed, or miss content that only exists in page images. ' +
            'Read the WHOLE content carefully, match the question by meaning (synonyms, different wording, Arabic spelling variants like أ/ا and ة/ه, or the same idea in English/Arabic), and rebuild fragmented sentences before deciding. ' +
            'Your answer has TWO clearly separated parts: ' +
            '(A) "from_lecture": what the LECTURE CONTENT below itself says about the question — answer it directly and completely using only the lecture, in clear plain language, ' +
            'quoting the lecture\'s own terms, definitions, steps and numbers where relevant (roughly 3 to 7 sentences; use short numbered lines like "1) ..." if the answer has steps or several points). ' +
            'If the lecture covers the topic only partly or indirectly, give what it does say and state clearly which part it does not mention. ' +
            'ONLY if, after a thorough search, the topic is truly absent, set from_lecture to "المحاضرة مش بتتكلم عن النقطة دي بشكل مباشر." — never use this when related content exists. '+
            '(B) "from_gemini": what YOU add from your own general knowledge to make the answer more complete and easier to understand — a fuller explanation, a helpful real-world example, ' +
            'important details or common exam pitfalls that the lecture leaves out (roughly 3 to 7 sentences). Do NOT just repeat part A, and it must stay consistent with the lecture; if you know of a difference from the lecture, mention it politely. ' +
            'If the lecture does not cover the question, from_gemini must give the complete answer from your own knowledge. ' +
            'If the question is trivial and there is truly nothing useful to add, keep from_gemini to one short sentence. ' +
            safety +
            'Formatting: NEVER use markdown (no **bold**, no #headers, no asterisks). Plain text only; simple numbered lines like "1) ..." are allowed. ' +
            'Respond with ONLY valid JSON, no markdown fences, no commentary. JSON shape: {"flagged":false,"from_lecture":"...","from_gemini":"..."}. ' +
            'Answer in Arabic if the question is in Arabic, otherwise match the question language.\n\n' +
            `Subject: ${subject}\nStudent question: ${question}\n\nLecture content` +
            (images.length
              ? (trimmedText ? `:\n\n${trimmedText}\n\n(The attached images are the lecture's pages - use them too, they may contain content missing from the text above.)`
                             : ' (read the text in the attached scanned pages):')
              : `:\n\n${trimmedText}`);
        } else {
        instructions =
          'You are a patient private tutor chatting with a student about their lecture, like a WhatsApp conversation — NOT writing an article. ' +
          'Use the given lecture content as your source of truth (you may also draw on general subject knowledge to explain better, ' +
          'but stay consistent with what the lecture says). ' +
          safety +
          'STRICT rules for non-abusive questions: ' +
          '(1) Default answer length is SHORT — 2 to 5 sentences. If the question is just "what does X mean / define X", give ONLY a short plain-language definition, nothing else — no example unless asked. ' +
          '(2) Only give a worked example if the student is asking about a rule/law/problem they are confused about, or explicitly asks for an example — and even then keep it to ONE compact example, not multiple paragraphs. ' +
          '(3) NEVER use markdown formatting of any kind — no **bold**, no #headers, no bullet asterisks, no numbered-list markers. Plain conversational sentences only, like you are texting a friend. ' +
          '(4) End with a short, casual one-line offer like "قولّي لو عايز مثال" ONLY if you did not already give one — do not pad the answer with this every time. ' +
          '(5) If the student says something like "still don\'t get it" or asks for another example, give ONE different, simpler concrete example — still short. ' +
          'If the lecture genuinely does not cover what they are asking, say so honestly in one line instead of guessing. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. JSON shape: {"flagged":false,"answer":"..."}. ' +
          'Answer in Arabic if the question is in Arabic, otherwise match the question language.\n\n' +
          `Subject: ${subject}\nStudent question: ${question}\n\nLecture content` +
          (images.length ? ' (read the text in the attached scanned pages):' : `:\n\n${trimmedText}`);
        }
      } else {
        instructions =
          'You are an exam-question generator for a university lecture. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
          'JSON shape: {"questions":[{"type":"mcq","question":"...","options":["A","B","C","D"],"correct_index":0,"explanation":"..."}]}. ' +
          'Mix mcq and short_answer types (short_answer omits options/correct_index and instead has "model_answer"). ' +
          difficultyNote + ' ' +
          'Base every question strictly on the given lecture content. Write questions in Arabic if the content is in Arabic, otherwise match the source language.\n\n' +
          `Subject: ${subject}\nGenerate exactly ${count} exam questions` +
          (images.length ? ' from these scanned lecture pages (read the text in the images):' : ` from this lecture content:\n\n${trimmedText}`);
      }

      const parts = [{ text: instructions }];
      for (const img of images) {
        if (img && img.data) parts.push({ inlineData: { mimeType: img.mimeType || 'image/jpeg', data: img.data } });
      }

      // ---- ask mode gets its own handling: Gemini's own safety filters often
      // block a response outright when the question itself is abusive, which
      // would otherwise throw and skip logging/moderation entirely. Treat any
      // failure here as flagged content rather than a generic technical error. ----
      if (mode === 'ask') {
        const studentName = (body.student || 'غير معروف').toString().slice(0, 60);
        let result;
        let flagged = false;
        try {
          result = await callGemini(env, parts);
          flagged = !!result.flagged;
          if (body.dual === true && !flagged) {
            const fl = String(result.from_lecture || '').trim();
            const fg = String(result.from_gemini || '').trim();
            result = {
              flagged: false,
              from_lecture: fl,
              from_gemini: fg,
              answer: '📘 من المحاضرة:\n' + fl + '\n\n✨ من Gemini:\n' + fg,
            };
          }
        } catch (e) {
          if (e && e.safetyBlocked) {
            flagged = true;
            result = { answer: '' };
          } else {
            // quota / network / bad JSON etc. is NOT student misconduct:
            // never log it as abuse and never count it toward an auto-ban.
            throw e;
          }
        }

        if (env.QUIZ_KV) {
          const rawLog = await env.QUIZ_KV.get('ai_log');
          const logList = rawLog ? JSON.parse(rawLog) : [];
          logList.push({
            at: Date.now(), ip, student: studentName, subject,
            question: (body.raw_question ? String(body.raw_question).slice(0, 500) : question),
            answer: flagged ? '' : (result.answer || ''), flagged,
          });
          await env.QUIZ_KV.put('ai_log', JSON.stringify(logList.slice(-300))); // keep last 300
        }

        if (flagged) {
          const AUTO_BAN_AFTER = 2; // flagged messages from the same device before auto-ban
          let offenseCount = 1;
          if (env.QUIZ_KV) {
            const flagKey = 'flag_count:' + ip;
            const countRaw = await env.QUIZ_KV.get(flagKey);
            offenseCount = (countRaw ? parseInt(countRaw) : 0) + 1;
            await env.QUIZ_KV.put(flagKey, String(offenseCount), { expirationTtl: 60 * 60 * 24 }); // offense count resets after a clean day
          }

          if (offenseCount >= AUTO_BAN_AFTER) {
            if (env.QUIZ_KV) {
              const bannedRaw2 = await env.QUIZ_KV.get('banned_users');
              const bannedList2 = bannedRaw2 ? JSON.parse(bannedRaw2) : [];
              if (bannedList2.indexOf(ip) === -1) bannedList2.push(ip);
              await env.QUIZ_KV.put('banned_users', JSON.stringify(bannedList2));
            }
            return jsonResponse({ flagged: true, answer: 'تم حظرك تلقائياً من استخدام الذكاء الاصطناعي بسبب تكرار الإساءة.' });
          }

          return jsonResponse({
            flagged: true,
            answer: 'ممنوع استخدام ألفاظ أو أسلوب مسيء — الرجاء الالتزام بالأدب. تكرار ده هيؤدي لحظرك تلقائياً من استخدام الذكاء الاصطناعي.',
          });
        }

        return jsonResponse(result);
      }

      const result = await callGemini(env, parts);

      if (cacheKey && env.QUIZ_KV) {
        await env.QUIZ_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL_SECONDS });
      }

      return jsonResponse(result);
    } catch (e) {
      const status = e && e.status === 429 ? 429 : 502;
      return jsonResponse({ error: e && e.message ? e.message : String(e) }, status);
    }
  },
};
