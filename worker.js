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
const BUILD_VERSION = 'v5.7-ai-video-public-visual-accuracy-notif-fallback';
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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-JustM-Action',
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

// Per-student limits (by Firebase uid, incl. the device's anonymous identity) so
// people sharing one IP (campus Wi-Fi / mobile carrier NAT) don't eat each other's
// quota. A looser per-IP ceiling stays on top so scripts can't dodge limits by
// minting endless anonymous accounts.
const IP_CEILING_MULTIPLIER = 5;

async function bumpLimit(env, id, perMin, perDay) {
  const minuteKey = 'rl:min:' + id;
  const dayKey = 'rl:day:' + id;
  const [minuteRaw, dayRaw] = await Promise.all([env.QUIZ_KV.get(minuteKey), env.QUIZ_KV.get(dayKey)]);
  const minuteCount = minuteRaw ? parseInt(minuteRaw) : 0;
  const dayCount = dayRaw ? parseInt(dayRaw) : 0;
  if (minuteCount >= perMin) return 'كتّرت الطلبات في دقيقة واحدة — استنى دقيقة وجرب تاني.';
  if (dayCount >= perDay) return 'وصلت للحد الأقصى من طلبات الذكاء الاصطناعي المسموحة لك اليوم — جرب تاني بكرة.';
  await Promise.all([
    env.QUIZ_KV.put(minuteKey, String(minuteCount + 1), { expirationTtl: 60 }),
    env.QUIZ_KV.put(dayKey, String(dayCount + 1), { expirationTtl: 60 * 60 * 24 }),
  ]);
  return null;
}

async function checkRateLimit(env, ip, uid) {
  if (!env.QUIZ_KV) return null; // fail open if KV unavailable
  if (uid) {
    const userMsg = await bumpLimit(env, 'u:' + uid, RATE_LIMIT_PER_MINUTE, RATE_LIMIT_PER_DAY);
    if (userMsg) return userMsg;
    if (!ip) return null;
    return await bumpLimit(env, ip, RATE_LIMIT_PER_MINUTE * IP_CEILING_MULTIPLIER, RATE_LIMIT_PER_DAY * IP_CEILING_MULTIPLIER);
  }
  if (!ip) return null;
  return await bumpLimit(env, ip, RATE_LIMIT_PER_MINUTE, RATE_LIMIT_PER_DAY);
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
// ---- owner-only "JustM summary designer": text/photos of a lecture -> structured study sheet ----
const DESIGN_SUMMARY_SCHEMA = {
  type: 'OBJECT',
  properties: {
    title: { type: 'STRING' },
    subtitle: { type: 'STRING' },
    lecture_line: { type: 'STRING' },
    sections: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          label: { type: 'STRING' },
          title: { type: 'STRING' },
          blocks: {
            type: 'ARRAY',
            items: {
              type: 'OBJECT',
              properties: {
                type: { type: 'STRING' },
                title: { type: 'STRING' },
                badge: { type: 'STRING' },
                text: { type: 'STRING' },
                items: { type: 'ARRAY', items: { type: 'STRING' } },
                numbered: { type: 'BOOLEAN' },
                formula: { type: 'STRING' },
                table: {
                  type: 'OBJECT',
                  properties: {
                    headers: { type: 'ARRAY', items: { type: 'STRING' } },
                    rows: { type: 'ARRAY', items: { type: 'ARRAY', items: { type: 'STRING' } } }
                  }
                }
              },
              required: ['type']
            }
          }
        },
        required: ['title', 'blocks']
      }
    }
  },
  required: ['title', 'sections']
};

const PROMPT_VERSIONS = { video_script: '5', video_explain: '15', video_brain: '3' };

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
          section_label: { type: 'STRING' },
          lecture: { type: 'STRING' },
          board: {
            type: 'OBJECT',
            properties: {
              sections: {
                type: 'ARRAY',
                items: {
                  type: 'OBJECT',
                  properties: {
                    label: { type: 'STRING' },
                    kind: { type: 'STRING' },
                    items: { type: 'ARRAY', items: { type: 'STRING' } }
                  }
                }
              }
            }
          },
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
          calc_steps: {
            type: 'ARRAY',
            items: { type: 'OBJECT', properties: { label: { type: 'STRING' }, formula: { type: 'STRING' }, numbers: { type: 'STRING' }, result: { type: 'STRING' } } }
          },
          problem: {
            type: 'OBJECT',
            properties: {
              statement: { type: 'STRING' },
              requirement: { type: 'STRING' },
              final: { type: 'STRING' },
              tables: {
                type: 'ARRAY',
                items: {
                  type: 'OBJECT',
                  properties: {
                    title: { type: 'STRING' },
                    headers: { type: 'ARRAY', items: { type: 'STRING' } },
                    rows: { type: 'ARRAY', items: { type: 'ARRAY', items: { type: 'STRING' } } }
                  }
                }
              },
              answers: {
                type: 'ARRAY',
                items: { type: 'OBJECT', properties: { label: { type: 'STRING' }, formula: { type: 'STRING' }, numbers: { type: 'STRING' }, result: { type: 'STRING' } } }
              }
            }
          },
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
  const requestBody = JSON.stringify({
    contents: [{ role: 'user', parts }],
    generationConfig: config,
  });

  // Gemini/edge 502/503/504/524 errors are often transient. Retry a small,
  // bounded number of times before returning control to the saved video job.
  // Do not retry permanent 4xx errors (except temporary rate limiting).
  let apiResponse = null;
  let lastTransientStatus = 0;
  const maxAttempts = 2; // initial attempt + one retry, to avoid duplicate long generations
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      apiResponse = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
        body: requestBody,
      });
    } catch (networkError) {
      if (attempt + 1 >= maxAttempts) {
        throw Object.assign(new Error('تعذّر الاتصال بخدمة Gemini مؤقتًا. التقدم المحفوظ آمن؛ اضغط «استكمال» بعد قليل.'), { status: 503 });
      }
      await new Promise(resolve => setTimeout(resolve, 900));
      continue;
    }
    if (apiResponse.ok) break;
    lastTransientStatus = apiResponse.status;
    const retryable = [429, 500, 502, 503, 504, 524].includes(apiResponse.status);
    if (!retryable || attempt + 1 >= maxAttempts) break;
    // Consume body before retrying so the response connection can be released.
    try { await apiResponse.text(); } catch (_) {}
    await new Promise(resolve => setTimeout(resolve, apiResponse.status === 429 ? 1400 : 900));
  }

  if (!apiResponse || !apiResponse.ok) {
    const status = apiResponse ? apiResponse.status : lastTransientStatus;
    let errText = '';
    try { errText = apiResponse ? await apiResponse.text() : ''; } catch (_) {}
    if (status === 524 || status === 504 || status === 502 || status === 503) {
      const err = new Error('خدمة Gemini اتأخرت أو انتهت مهلة الاتصال (HTTP ' + status + '). التقدم محفوظ؛ انتظر قليلًا ثم اضغط «استكمال» لإعادة المحاولة من المرحلة المتوقفة.');
      err.status = 503;
      err.upstreamStatus = status;
      throw err;
    }
    const err = new Error('Gemini API error: ' + (errText || ('HTTP ' + status)));
    err.status = status || 502;
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
  if (file.size > 100 * 1024 * 1024) return jsonResponse({ error: 'الفيديو أكبر من الحد المسموح (100MB).' }, 413);
  const baseTs = Math.floor(Date.now() / 1000);
  const safeId = ('justm_ai_' + account.uid + '_' + baseTs).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 120);
  const folder = 'justm_ai_videos';
  // fl_attachment must live in the SAME transformation as the MP4 conversion:
  // it makes the WebView treat the URL as a download (not inline playback) and the
  // converted file is pre-built at upload time (no partial first-request transcode).
  const eagerOptions = ['fl_attachment,f_mp4,vc_h264,ac_aac', 'f_mp4,vc_h264,ac_aac', null];
  let data = {};
  let cloud = null;
  let usedEager = null;
  for (const eager of eagerOptions) {
    const timestamp = Math.floor(Date.now() / 1000);
    const params = (eager ? `eager=${eager}&` : '') + `folder=${folder}&public_id=${safeId}&timestamp=${timestamp}`;
    const signature = await sha1Hex(params + env.CLOUDINARY_API_SECRET);
    const up = new FormData();
    up.append('file', file, filename);
    up.append('api_key', env.CLOUDINARY_API_KEY);
    up.append('timestamp', String(timestamp));
    if (eager) up.append('eager', eager);
    up.append('folder', folder);
    up.append('public_id', safeId);
    up.append('signature', signature);
    cloud = await fetch(`https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/video/upload`, { method: 'POST', body: up });
    data = await cloud.json().catch(() => ({}));
    if (cloud.ok && data.secure_url) { usedEager = eager; break; }
    // retry with a simpler option only when the failure looks transformation-related
    if (!/eager|transform|flag|invalid/i.test(String(data.error && data.error.message || ''))) break;
  }
  if (!cloud || !cloud.ok || !data.secure_url) return jsonResponse({ error: (data.error && data.error.message) || `Cloudinary upload failed (${cloud && cloud.status})` }, 502);
  const eagerUrl = data.eager && data.eager[0] && data.eager[0].secure_url;
  return jsonResponse({ ok: true, secure_url: eagerUrl || data.secure_url, converted: !!eagerUrl, bytes: file.size, filename });
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

      // video_explain/video_tts accept anonymous device identity too; owner-only
      // operations below still require verifyOwner. Rate limiting remains active.

      // ---- published AI explainer videos: the owner generates + publishes once, students only watch ----
      const PUBVID_PREFIX = 'pubvid:';
      const MAX_PUBLISHED_PER_LECTURE = 12;
      if (mode === 'video_get') {
        const lectureUrl = String(body.lecture_url || '').trim().slice(0, 1500);
        if (!lectureUrl || !env.QUIZ_KV) return jsonResponse({ videos: [] });
        const rawList = await env.QUIZ_KV.get(PUBVID_PREFIX + (await sha256Hex(lectureUrl)));
        let list = []; try { list = rawList ? JSON.parse(rawList) : []; } catch (e) { list = []; }
        return jsonResponse({ videos: Array.isArray(list) ? list : [] });
      }

      const OWNER_ONLY_MODES = ['get_ai_log', 'get_banned', 'ban_user', 'unban_user', 'video_env_check', 'video_start', 'video_poll', 'video_generate', 'course_level_summary', 'video_explain', 'video_tts', 'video_publish', 'video_unpublish', 'design_summary'];
      if (OWNER_ONLY_MODES.includes(mode)) {
        // FIX: these four used to run with no check at all. Now the Worker
        // verifies the caller's Firebase ID token itself and requires the
        // "owner" role, instead of trusting whatever the client sends.
        const account = await verifyOwner(request, env);
        if (!account || account.role !== 'owner') {
          return jsonResponse({ error: 'unauthorized' }, 403);
        }
      }

      if (mode === 'video_publish' || mode === 'video_unpublish') {
        const lectureUrl = String(body.lecture_url || '').trim().slice(0, 1500);
        const videoUrl = String(body.video_url || '').trim().slice(0, 1500);
        if (!lectureUrl || !env.QUIZ_KV) return jsonResponse({ error: 'bad request' }, 400);
        const listKey = PUBVID_PREFIX + (await sha256Hex(lectureUrl));
        let list = []; try { const r = await env.QUIZ_KV.get(listKey); list = r ? JSON.parse(r) : []; } catch (e) { list = []; }
        if (!Array.isArray(list)) list = [];
        if (mode === 'video_unpublish') {
          list = list.filter((v) => v && v.url !== videoUrl);
        } else {
          // only our own courses-worker R2 file urls may be published (no arbitrary links)
          if (videoUrl.indexOf(COURSES_WORKER_ORIGIN + '/?action=file&k=') !== 0) return jsonResponse({ error: 'invalid video url' }, 400);
          list = list.filter((v) => v && v.url !== videoUrl);
          list.unshift({
            url: videoUrl,
            title: String(body.title || 'شرح بالفيديو').slice(0, 150),
            explain_mode: ['theory', 'intensive', 'comprehensive'].includes(body.explain_mode) ? body.explain_mode : '',
            scenes: Math.max(0, Math.min(60, parseInt(body.scenes, 10) || 0)),
            at: Date.now(),
          });
          list = list.slice(0, MAX_PUBLISHED_PER_LECTURE);
        }
        await env.QUIZ_KV.put(listKey, JSON.stringify(list));
        return jsonResponse({ ok: true, videos: list });
      }

      // ---- owner-only: analyze a course's existing hosted video -> study notes, in 3 short steps so the app
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

      // ---- owner-only: merge every course video's notes into ONE level-wide summary ----
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
      // ---- owner-only: design a JustM-style study sheet from lecture text / photos ----
      if (mode === 'design_summary') {
        const text = String(body.text || '').trim().slice(0, 60000);
        const images = Array.isArray(body.images) ? body.images.slice(0, 12) : [];
        if (!text && !images.length) return jsonResponse({ error: 'اكتب نص المحاضرة أو ارفع صورها' }, 400);
        const titleHint = String(body.title || '').trim().slice(0, 200);
        const subHint = String(body.subtitle || '').trim().slice(0, 200);
        const brief = body.detail === 'brief';
        const dprompt =
          'أنت أستاذ جامعي عربي تُعدّ ملخص مذاكرة مصممًا على طريقة ملفات JustM المرتبة. حوّل مادة المحاضرة المرفقة (نص و/أو صور صفحات أو سبورة أو خط يد) إلى ملف دراسة منظم. ' +
          'اقرأ الصور بعناية واستخرج كل ما فيها حرفيًا بما في ذلك الأرقام والقوانين والجداول، وصحّح الأخطاء الإملائية الواضحة فقط. لا تخترع معلومة ولا رقمًا غير موجود في المادة، ولا تغيّر مصطلحات المحاضرة. ما لا يُقرأ بوضوح اكتبه كما يبدو أو اتركه. ' +
          (brief ? 'المستوى: مختصر ومركّز للمراجعة السريعة، لكن لا تُسقط تعريفًا أو قانونًا أو رقمًا مهمًا. ' : 'المستوى: كامل ومفصّل، يغطي كل نقاط المحاضرة بالترتيب دون إسقاط تعريف أو قانون أو مثال أو ملاحظة. ') +
          'قسّم الملف إلى أقسام بنفس ترتيب المحاضرة؛ لكل قسم label ترتيبي ("أولاً" ثم "ثانياً" ثم "ثالثاً" ...) وtitle هو اسم القسم، وداخله blocks بالأنواع التالية فقط: ' +
          'definition (تعريف أو مفهوم أساسي)، info (معلومة أو شرح مكمّل)، warning (تنبيه أو أخطاء شائعة أو عيوب أو استثناءات)، example (مثال أو تطبيق أو فائدة)، note (ملاحظة سريعة)، summary (خلاصة أو أهداف أو استخدامات)، table (جدول أو مقارنة)، formula (قانون أو معادلة)، paragraph (فقرة عادية بدون صندوق). ' +
          'لكل block: title عنوان قصير للصندوق (بدون رموز تعبيرية)، badge يكون "مهم" أو "مهم جداً" فقط للنقاط التي يُتوقع أن تأتي في الامتحان وإلا اتركه فارغًا، text شرح بجمل واضحة، items قائمة نقاط (ومعها numbered=true إذا كانت خطوات أو ترتيبًا، وإلا false). ' +
          'في أي نص أو نقطة: ضع الكلمة أو العبارة المهمة (مصطلح أو رقم أو قاعدة) بين [[ ]] للتظليل الأصفر، من 1 إلى 3 تظليلات في الصندوق الواحد وبحد أقصى كلمات قليلة لكل تظليل، واكتب عنوان النقطة داخل القائمة بين ** ** بالشكل **العنوان:** الشرح. ' +
          'للمقارنات بين شيئين أو أكثر استخدم table ببنية headers وrows (العمود الأول اسم العنصر المقارَن)، وللقوانين استخدم formula بنص المعادلة نفسه مع title اسم القانون، ولا تكرر محتوى الجدول في text. ' +
          'لا تستخدم markdown غير ** ** و[[ ]]، ولا HTML، ولا رموز تعبيرية. ابدأ بـ title عنوان المحاضرة، وsubtitle اسم المادة/الدكتور إن ذُكر في المادة، وlecture_line جملة قصيرة تعرّف المحاضرة (مثل: المحاضرة السابعة — النظرية الكينزية). ' +
          (titleHint ? ('عنوان المحاضرة المطلوب حرفيًا: ' + titleHint + '. ') : '') +
          (subHint ? ('سطر المادة المطلوب حرفيًا: ' + subHint + '. ') : '') +
          'أرجع JSON صالحًا فقط.' +
          (text ? ('\n\nنص المحاضرة:\n' + text) : '');
        const dparts = [{ text: dprompt }];
        for (const img of images) {
          if (img && img.mimeType && img.data) dparts.push({ inlineData: { mimeType: String(img.mimeType), data: String(img.data) } });
        }
        let draw;
        try {
          draw = await callGemini(env, dparts, { maxOutputTokens: 32000, responseMimeType: 'application/json', responseSchema: DESIGN_SUMMARY_SCHEMA, temperature: 0.2 });
        } catch (e1) {
          if (e1 && e1.status === 502) {
            draw = await callGemini(env, [{ text: dprompt + '\n\nإعادة محاولة: أخرج JSON كاملًا وصالحًا فقط واجعل الصياغة أكثر إيجازًا.' }].concat(dparts.slice(1)), { maxOutputTokens: 20000, responseMimeType: 'application/json', responseSchema: DESIGN_SUMMARY_SCHEMA, temperature: 0.1 });
          } else { throw e1; }
        }
        const keep = (v, n) => String(v == null ? '' : v).replace(/[#`<>]/g, '').trim().slice(0, n || 4000);
        draw = draw && typeof draw === 'object' ? draw : {};
        const TYPES = ['definition', 'info', 'warning', 'example', 'note', 'summary', 'table', 'formula', 'paragraph'];
        const dsections = (Array.isArray(draw.sections) ? draw.sections : []).slice(0, 25).map((sec) => ({
          label: keep(sec && sec.label, 20),
          title: keep(sec && sec.title, 200),
          blocks: (Array.isArray(sec && sec.blocks) ? sec.blocks : []).slice(0, 20).map((b) => {
            b = b && typeof b === 'object' ? b : {};
            let table = null;
            if (b.table && Array.isArray(b.table.rows) && b.table.rows.length) {
              table = {
                headers: (Array.isArray(b.table.headers) ? b.table.headers : []).slice(0, 6).map((c) => keep(c, 200)),
                rows: b.table.rows.slice(0, 30).map((r) => (Array.isArray(r) ? r.slice(0, 6).map((c) => keep(c, 400)) : [])).filter((r) => r.length)
              };
            }
            return {
              type: TYPES.includes(String(b.type)) ? String(b.type) : 'paragraph',
              title: keep(b.title, 200),
              badge: /جداً|جدا/.test(String(b.badge || '')) ? 'مهم جداً' : (/مهم/.test(String(b.badge || '')) ? 'مهم' : ''),
              text: keep(b.text, 3000),
              items: (Array.isArray(b.items) ? b.items : []).slice(0, 14).map((i) => keep(i, 900)).filter(Boolean),
              numbered: !!b.numbered,
              formula: keep(b.formula, 400),
              ...(table ? { table } : {})
            };
          }).filter((b) => b.title || b.text || b.items.length || b.formula || b.table)
        })).filter((sec) => sec.title && sec.blocks.length);
        if (!dsections.length) return jsonResponse({ error: 'DESIGN_EMPTY', message: 'ما قدرتش أطلّع أقسام من المادة، جرّب صور أوضح أو نص أكتر.' }, 502);
        return jsonResponse({ doc: { title: keep(draw.title || titleHint || 'ملخص المحاضرة', 200), subtitle: keep(draw.subtitle || subHint, 200), lecture_line: keep(draw.lecture_line, 300), sections: dsections } });
      }

      if (mode === 'video_explain') {
        const text = String(body.text || '').trim().slice(0, 70000);
        const images = Array.isArray(body.images) ? body.images.slice(0, 12) : [];
        const subject = String(body.subject || 'المادة').slice(0, 120);
        const request = String(body.request || '').trim().slice(0, 3000);
        if (!text && !images.length) {
          return jsonResponse({ error: 'محتوى المحاضرة مطلوب' }, 400);
        }
        const effectiveRequest = request || 'اشرح المحاضرة كاملة من البداية للنهاية، مع الحفاظ على ترتيب الأفكار وعدم إسقاط النقاط الأساسية.';

        const explainMode = ['theory', 'intensive', 'comprehensive'].includes(body.explain_mode) ? body.explain_mode : '';
        const MODE_LENGTH = {
          theory: 'اجعل الفيديو النظري لهذا الجزء نحو دقيقة إلى دقيقتين إجمالًا (150 إلى 300 كلمة). اشرح الفكرة والتعريف والأهمية بوضوح من المصدر مع كتابة المحتوى النظري كاملًا على السبورة.',
          intensive: 'سرد كل مشهد من 60 إلى 110 كلمة، أسلوب سريع ومباشر، والأولوية للقوانين والأرقام وخطوات الحل على السبورة.',
          comprehensive: 'شرح تفصيلي بدون أي تلخيص، وحدد طول كل لوحة حسب صعوبتها: (أ) نظري: اشرحه كاملًا مع توضيح أي مصطلح، من 100 إلى 220 كلمة، واكتب التعريفات والنقاط كاملة على السبورة. (ب) عملي مباشر (مثل القوائم المالية): اذكر القانون بالكلام ثم عوّض بالأرقام الفعلية بندًا بندًا ثم الناتج، من 150 إلى 300 كلمة. (ج) مسألة كبيرة أو قوانين متعددة: اشرحها بالتفصيل وحل الأمثلة خطوة خطوة، من 400 إلى 600 كلمة كحد أقصى. راجع كل عملية حسابية مرتين واستخدم أرقام الملف نفسها.'
        };
        const modeRules = explainMode ? ('قواعد الطول الخاصة بالنمط المختار: ' + MODE_LENGTH[explainMode] + ' ') : '';
        const partTotal = Math.max(1, Math.min(8, parseInt(body.part_total, 10) || 1));
        const sceneTarget = Math.max(1, Math.min(12, parseInt(body.scene_target, 10) || 4));
        const partRule = partTotal > 1 ? ('هذه الدفعة جزء من محاضرة مقسمة على ' + partTotal + ' دفعات: اكتب حوالي ' + sceneTarget + ' مشاهد لهذه الدفعة فقط، واجعل كل مشهد غنيًا بالمحتوى المكتوب على الشاشة. مشاهد الامتحان تُكتب فقط في آخر دفعة. ') : '';

        const boardRules =
          'القاعدة الذهبية — السبورة بتشرح مش بتعرض عناوين: تخيّل أن الطالب كاتم الصوت وبيذاكر من الشاشة فقط، فلازم يلاقي صفحة ملخص كاملة زي ملفات JustM. ' +
          '(1) لوحة واحدة لكل قسم رئيسي في المصدر (أولاً، ثانياً...): visual_type="board" وفيها board.sections من 1 إلى 3 أقسام تظهر على نفس السبورة مع بعض، مثل: قسم «مفهوم» ثم قسم «أهمية» ثم «أنواع» أو «شروط» أو «خصائص»، بترتيب المصدر. ' +
          '(2) كل قسم {label,kind,items}: label كلمة أو اثنتين (مفهوم، أهمية، أنواع، شروط، خصائص، خطوات، تنبيه)، وkind واحدة من: concept, importance, types, conditions, features, steps, example, warning. items من 1 إلى 5 عناصر (الواجهة بترقّمها تلقائيًا)، وكل عنصر بصيغة «[[العنوان]]: جملة أو جملتين تحمل المعلومة نفسها من المصدر». التعريف يُكتب كاملًا ودقيقًا كأول عنصر في قسم المفهوم، ولو طويل قسّمه لأركانه. ' +
          '(3) إجمالي عناصر اللوحة 8 كحد أقصى؛ لو القسم أكبر قسّمه على لوحتين. ' +
          '(4) ممنوع تمامًا المربعات ذات الكلمة الواحدة بدون مضمونها (مثل "تعريف" أو "أهمية" لوحدها). لا تستخدم concept_map أو flow. ' +
          '(5) لو في المصدر أشياء تُقارن أو تُصنّف (مصطلحات، أنواع، مفاهيم متقابلة) استخدم visual_type="table" بجدول كامل في table (حتى 5 أعمدة و10 صفوف). وللقانون النظري visual_type="formula": الصيغة في emphasis[0] وفي bullets مدلول كل رمز ومتى يُستخدم. ' +
          '(6) المكتوب هو الهيكل والمعلومة الأساسية، والمنطوق في narration هو الشرح والسبب والتبسيط والمثال. ' +
          '(7) لا تكرر نفس المعلومة في لوحتين، ولا تكتب مثالًا أو رقمًا غير موجود في المصدر، ولا تضع example=true إلا لو المصدر فيه مثال فعلاً. ';

        const problemRules =
          'الأسئلة المحلولة والجداول الجاهزة والأمثلة بالأرقام: أي مشهد فيه أرقام أو حساب أو قائمة مالية أو مثال محلول يجب أن يكون visual_type="problem" والمدرس يفهم المسألة ويعيد صياغتها بنفسه: ' +
          '(1) problem.statement = نص السؤال كاملًا بصياغة واضحة كما يُطرح في الامتحان، مبني على معطيات المصدر فقط، حتى لو المصدر عارض الجدول المحلول بدون سؤال صريح؛ فاستنتج السؤال من الجدول وطريقة الحل ولا تخترع أي رقم. ' +
          '(2) problem.tables: جدول المعطيات كما كان قبل الحل (عمود البيان وعمود المبلغ، وعمود ثالث للملاحظة عند الحاجة) بكل أرقام وبنود المصدر (حتى 3 جداول، 16 صفًا، 5 أعمدة). ' +
          '(3) problem.requirement: جملة المطلوب بدقة. ' +
          '(4) problem.answers: كل خطوة حل بالترتيب نفسه وبطريقة الحل نفسها الموجودة في المصدر (حتى 8) بصيغة {label,formula,numbers,result}: label اسم البند، formula القانون بالكلمات، numbers التعويض بالأرقام، result الناتج مع الوحدة. لا تقفز للناتج النهائي وراجع الحسابات مرتين. ' +
          '(5) problem.final: جملة النتيجة النهائية. ' +
          '(6) في narration: اقرأ السؤال أولًا بصياغتك ثم اشرح الحل خطوة خطوة. لا تضع source_image_index في مشاهد problem إلا لو الصفحة فيها جدول معقد يصعب نقله. ';

        const examRules =
          'مشاهد الامتحان في آخر الفيديو (إلزامي في آخر دفعة): بعد شرح كل المحتوى أضف مشهدًا أو مشهدين أخيرين visual_type="board" وkind="exam" وsection_label="للامتحان" وlecture="أسئلة متوقعة للامتحان"، فيهم قسم واحد kind="exam" وlabel="ممكن يجيلك في الامتحان" وitems من 3 إلى 5 أسئلة متوقعة مبنية على المصدر بصيغة «[[نوع السؤال]]: نص السؤال المتوقع» (مثل: عرّف...؟ اذكر أهمية...؟ ما الفرق بين...؟ حل المسألة التالية...). في narration قل للطالب إنه ممكن يجيله في الامتحان سؤال بصيغة كذا، وبعدها لمّح بإجابة مختصرة لكل سؤال. ';

        const lectureRules =
          'تعدد المحاضرات: لو الملف ملخص لأكثر من محاضرة أو موضوع رئيسي، اكتب في كل مشهد الحقل lecture بعنوان موضوع المحاضرة التي ينتمي لها (نفس النص بالحرف في كل مشاهد المحاضرة الواحدة) والواجهة هتغيّر لون الهيدر وتكتب عليه موضوع المحاضرة. لو الملف محاضرة واحدة اكتب موضوعها نفسه في كل المشاهد. ';

        const structureRules =
          'التنظيم والتظليل وربط الصوت بالسبورة: ' +
          '(أ) لكل مشهد اكتب section_label ترتيبي ("أولاً"، "ثانياً"...) وtitle يعبر عن فكرة المشهد نفسه (مثل: "مفهوم تقييم الأداء" وليس عنوان الفصل كله). ' +
          '(ب) التظليل: في on_screen وbullets وعناصر board وخلايا الجداول، ضع المصطلح أو الرقم أو القاعدة المحورية بين [[ ]] (من 1 إلى 3 كلمات، وبحد أقصى 3 تظليلات في المشهد). ممنوع [[ ]] داخل narration أو الحقول الرقمية أو العنوان. ' +
          '(ج) التزامن بالعلامة ¶: قسّم narration إلى أجزاء مفصولة بالعلامة ¶ بحيث يظهر كل عنصر على السبورة لحظة نطقه: في board (جزء مقدمة قصيرة ¶ ثم جزء لكل عنصر بنفس ترتيب ظهوره: عناصر القسم الأول ثم الثاني). في problem (جزء للسؤال والجدول ¶ جزء للمطلوب ¶ جزء لكل خطوة في answers ¶ جزء للنتيجة النهائية). في cards وsteps وcompare (مقدمة ¶ جزء لكل نقطة في bullets). في formula (جزء للقانون ¶ جزء لكل نقطة في bullets). ';

        const prompt =
          'أنت أستاذ جامعي عربي تشرح على سبورة ذكية تفاعلية بأسلوب JustM. حوّل محتوى المحاضرة المرفقة إلى فيديو تعليمي متكامل يجمع بين الشرح الصوتي الدافئ والسبورة الغنية بالمحتوى المكتوب بوضوح. ' +
          'الأنماط الثلاثة: (1) النظري/المبسّط: شرح تفصيلي لكل التعريفات والخصائص والقواعد والاستثناءات مكتوبة ومشروحة على السبورة. (2) المكثّف: تركيز سريع على القوانين والمسائل وخطوات الحل بالأرقام. (3) الشامل: النظري الكامل أولًا ثم العملي والمسائل بالتفصيل خطوة بخطوة. ' +
          'اعتمد على النص والصور المرفقة فقط. لا تخترع معلومة ولا رقمًا. ممنوع الكلام الإنشائي العام مثل "من أهم النقاط"؛ اكتب المعلومة نفسها. ' +
          'قبل بناء المشاهد نفّذ AI Brain داخليًا وصنّف المادة في حقل brain (sections, definitions, lists, formulas, examples, tables, warnings). ' +
          'القيم المسموحة لـ visual_type هي فقط: board (لوحة مفهوم/أهمية/أنواع/شروط على سبورة واحدة، وهي الأساس للنظري)، card (تعريف واحد أو قاعدة)، cards (2-4 نقاط)، steps (خطوات أو مراحل)، compare (مقارنة بين طرفين)، table (جدول مقارنة أو تصنيف)، formula (قانون نظري)، problem (أي مسألة أو قائمة مالية بأرقام)، timeline (تسلسل زمني)، focus (تنبيه أو استثناء مهم)، source_image (صفحة مصدر مهمة). ' +
          'احسب duration بالثواني = عدد كلمات narration ÷ 2.5. ممنوع markdown داخل الحقول. أرجع JSON صالح فقط بهذا الشكل: ' +
          '{"title":"...","language":"ar","brain":{"topic":"...","sections":["..."],"definitions":[],"lists":[],"formulas":[],"examples":[],"tables":[],"warnings":[]},"scenes":[{"title":"...","section_label":"أولاً","lecture":"...","on_screen":"...","bullets":["..."],"board":{"sections":[{"label":"مفهوم","kind":"concept","items":["[[العنوان]]: الشرح"]}]},"narration":"...","duration":12,"kind":"theory","visual_type":"board","visual_focus":"...","emphasis":["..."],"draw_steps":["..."],"problem":{"statement":"...","requirement":"...","final":"...","tables":[{"title":"...","headers":["..."],"rows":[["..."]]}],"answers":[{"label":"...","formula":"...","numbers":"...","result":"..."}]},"example":false,"source_anchor":"...","source_facts":["..."],"table":{"headers":["..."],"rows":[["..."]]}}]}. ' +
          'الموضوع: ' + subject + '\n' +
          modeRules + partRule + boardRules + problemRules + examRules + lectureRules + structureRules +
          'النمط وطلب الطالب: ' + effectiveRequest + '\n\n' +
          'مادة المحاضرة:\n' + text;

        const parts = [{ text: prompt }];
        for (const img of images) {
          if (img && img.mimeType && img.data) {
            parts.push({ inlineData: { mimeType: String(img.mimeType), data: String(img.data) } });
          }
        }

        let result;
        try {
          result = await callGemini(env, parts, {
            maxOutputTokens: 48000,
            responseMimeType: 'application/json',
            responseSchema: VIDEO_SCRIPT_RESPONSE_SCHEMA,
            temperature: 0.2
          });
        } catch (firstErr) {
          if (firstErr && firstErr.status === 502) {
            const retryParts = [{ text: prompt + '\n\nإعادة محاولة تقنية: أخرج JSON صالحًا بالكامل بدون أي نص خارجه، واجعل المشاهد مركزة مع الحفاظ على كل التعريفات والنقاط والخطوات كاملة.' }];
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
          sections: Array.isArray(rawBrain.sections) ? rawBrain.sections.map(clean).filter(Boolean).slice(0, 30) : [],
          definitions: Array.isArray(rawBrain.definitions) ? rawBrain.definitions.map(clean).filter(Boolean).slice(0, 30) : [],
          lists: Array.isArray(rawBrain.lists) ? rawBrain.lists.map(clean).filter(Boolean).slice(0, 30) : [],
          formulas: Array.isArray(rawBrain.formulas) ? rawBrain.formulas.map(clean).filter(Boolean).slice(0, 30) : [],
          examples: Array.isArray(rawBrain.examples) ? rawBrain.examples.map(clean).filter(Boolean).slice(0, 30) : [],
          tables: Array.isArray(rawBrain.tables) ? rawBrain.tables.map(clean).filter(Boolean).slice(0, 30) : [],
          warnings: Array.isArray(rawBrain.warnings) ? rawBrain.warnings.map(clean).filter(Boolean).slice(0, 30) : []
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
              on_screen: chunk.slice(0, 260),
              bullets: [chunk.slice(0, 220)],
              narration: chunk,
              duration: 10,
              visual_type: 'card',
              example: false
            }));
          } else {
            return jsonResponse({
              error: 'VIDEO_SCRIPT_EMPTY',
              message: 'الـWorker استلم محتوى بدون نص قابل للتحويل إلى سيناريو.'
            }, 502);
          }
        }

        const BOARD_KINDS = ['concept', 'importance', 'types', 'conditions', 'features', 'steps', 'example', 'warning', 'exam'];
        result.scenes = rawScenes.slice(0, 40).map((x, i) => {
          x = x && typeof x === 'object' ? x : {};
          const title = clean(x.title || ('النقطة ' + (i + 1)));
          const onScreen = clean(x.on_screen || x.explanation || title);
          const narration = clean(x.narration || x.explanation || x.voiceover || x.script || onScreen || title).replace(/\[\[|\]\]/g, '');
          const sectionLabel = clean(x.section_label || '').replace(/\[\[|\]\]/g, '').slice(0, 14);
          const lecture = clean(x.lecture || '').replace(/\[\[|\]\]/g, '').slice(0, 90);
          let bullets = Array.isArray(x.bullets) ? x.bullets.map(clean).filter(Boolean).slice(0, 6) : [];
          const sourceAnchor = clean(x.source_anchor || '');
          const sourceFacts = Array.isArray(x.source_facts) ? x.source_facts.map(clean).filter(Boolean).slice(0, 8) : [];
          const kind = ['theory', 'definition', 'list', 'formula', 'example', 'table', 'summary', 'exam'].includes(String(x.kind)) ? String(x.kind) : 'theory';

          // سبورة كاملة: أقسام (مفهوم/أهمية/أنواع...) على لوحة واحدة، عناصرها مرقمة في الواجهة
          let board = null;
          if (x.board && typeof x.board === 'object' && Array.isArray(x.board.sections)) {
            let left = 8;
            const secs = [];
            for (const s of x.board.sections.slice(0, 3)) {
              if (!s || typeof s !== 'object' || left <= 0) continue;
              const items = (Array.isArray(s.items) ? s.items : []).map(clean).filter(Boolean).slice(0, Math.min(5, left));
              if (!items.length) continue;
              left -= items.length;
              secs.push({
                label: clean(s.label || '').replace(/\[\[|\]\]/g, '').slice(0, 30) || 'مفهوم',
                kind: BOARD_KINDS.includes(String(s.kind)) ? String(s.kind) : (kind === 'exam' ? 'exam' : 'features'),
                items
              });
            }
            if (secs.length) board = { sections: secs };
          }
          if (board && !bullets.length) bullets = board.sections.reduce((a, s) => a.concat(s.items), []).slice(0, 6);

          const allowedVisuals = ['board', 'card', 'cards', 'steps', 'compare', 'formula', 'timeline', 'table', 'source_image', 'focus', 'problem'];
          let visualType = allowedVisuals.includes(String(x.visual_type))
            ? String(x.visual_type)
            : (board ? 'board' : kind === 'definition' ? 'card' : kind === 'formula' ? 'formula' : kind === 'table' ? 'table' : kind === 'example' ? 'problem' : bullets.length >= 2 ? 'cards' : 'card');
          if (board && ['card', 'cards', 'steps', 'focus'].includes(visualType)) visualType = 'board';
          if (visualType === 'board' && !board) visualType = bullets.length >= 2 ? 'cards' : 'card';

          const visualFocus = clean(x.visual_focus || x.title || '');
          const emphasis = Array.isArray(x.emphasis) ? x.emphasis.map(clean).filter(Boolean).slice(0, 8) : [];
          const drawSteps = Array.isArray(x.draw_steps) ? x.draw_steps.map(clean).filter(Boolean).slice(0, 8) : [];

          let problem = null;
          if (x.problem && typeof x.problem === 'object') {
            const pTables = (Array.isArray(x.problem.tables) ? x.problem.tables : []).slice(0, 3).map((t) => ({
              title: clean((t && t.title) || ''),
              headers: (Array.isArray(t && t.headers) ? t.headers : []).slice(0, 5).map(clean),
              rows: (Array.isArray(t && t.rows) ? t.rows : []).slice(0, 16).map((r) => (Array.isArray(r) ? r.slice(0, 5).map((c) => clean(c)) : [])).filter((r) => r.length),
            })).filter((t) => t.rows.length);
            const pAnswers = (Array.isArray(x.problem.answers) ? x.problem.answers : []).slice(0, 8).map((z) => ({
              label: clean((z && z.label) || ''), formula: clean((z && z.formula) || ''), numbers: clean((z && z.numbers) || ''), result: clean((z && z.result) || ''),
            })).filter((z) => z.label && (z.numbers || z.result));
            const pStatement = clean(x.problem.statement || '').slice(0, 1200);
            const pRequirement = clean(x.problem.requirement || '').slice(0, 500);
            const pFinal = clean(x.problem.final || '').slice(0, 300);
            if (pStatement || pRequirement || pTables.length || pAnswers.length) {
              problem = { statement: pStatement, requirement: pRequirement, final: pFinal, tables: pTables, answers: pAnswers };
            }
          }

          let table = null;
          if (x.table && typeof x.table === 'object' && Array.isArray(x.table.headers) && Array.isArray(x.table.rows)) {
            table = {
              headers: x.table.headers.map(clean).filter(Boolean).slice(0, 5),
              rows: x.table.rows.slice(0, 10).map(r => Array.isArray(r) ? r.map(clean).slice(0, 5) : []).filter(r => r.length)
            };
            if (!table.headers.length || !table.rows.length) table = null;
          }

          return {
            title,
            ...(sectionLabel ? { section_label: sectionLabel } : {}),
            ...(lecture ? { lecture } : {}),
            on_screen: onScreen,
            bullets,
            ...(board ? { board } : {}),
            narration,
            duration: Math.max(5, Math.min(300, Number(x.duration) || 10)),
            kind,
            visual_type: visualType,
            ...(visualFocus ? { visual_focus: visualFocus } : {}),
            ...(emphasis.length ? { emphasis } : {}),
            ...(drawSteps.length ? { draw_steps: drawSteps } : {}),
            ...(problem ? { problem } : {}),
            example: !!x.example || visualType === 'problem',
            ...(sourceAnchor ? { source_anchor: sourceAnchor } : {}),
            ...(sourceFacts.length ? { source_facts: sourceFacts } : {}),
            ...(Number.isFinite(Number(x.source_image_index)) ? { source_image_index: Math.max(0, Math.min(images.length - 1, Number(x.source_image_index))) } : {}),
            ...(table ? { table } : {})
          };
        }).filter(x => x.narration);

        if (!result.scenes.length) {
          return jsonResponse({ error: 'VIDEO_NARRATION_EMPTY', message: 'لم يوجد نص شرح قابل للاستخدام.' }, 502);
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
        const rlUser = await verifyRealUser(request, env);
        const limitMsg = await checkRateLimit(env, ip, rlUser && rlUser.uid);
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
      const rlUser = await verifyRealUser(request, env);
        const limitMsg = await checkRateLimit(env, ip, rlUser && rlUser.uid);
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
          'You are an expert Arabic university lecturer creating a visually clear explainer video from the supplied lecture, in the style of a polished educational infographic: clear heading, organized cards, relevant icons, arrows only when the source supports a relationship, and readable concise on-screen text. ' +
          'Before planning scenes, inspect the full page count, text density, difficulty, and the number and variety of practical questions. Estimate a realistic duration from the amount of teaching actually needed. There is NO fixed target duration and NO universal 8-minute cap: short/simple files should produce short videos, while long, dense, or difficult files must receive enough time for complete teaching even if the video exceeds 8 minutes. Never pad a short video and never rush or omit content to meet a time target. ' +
          'Teach the supplied file faithfully and comprehensively. Explain every distinct concept, definition, objective, characteristic, classification, rule, formula, note, comparison, and meaningful exception in the source. Do NOT summarize in place of teaching, do NOT omit important details to shorten the video, and do NOT add a recap/summary scene unless the source itself requires one. Avoid only redundant repetition. Never invent facts, labels, numbers, categories, or relationships not supported by the source. If a detail is unclear or missing, say so or leave it out. ' +
          'PART 1 - theory: cover all meaningful theory from the file in coherent, well-paced visual infographic scenes. Use clear headings, organized cards, readable concise on-screen text, relevant icons, tables, and diagrams only where the source supports the relationship. Narration should teach the idea, not merely read bullets. ' +
          'PART 2 - practical (MANDATORY whenever the lecture contains solved examples, exercises, problems, calculations, journal entries, numerical tables, or case studies): inspect every practical item in source order and identify which ones test genuinely different methods, rules, or cases. Teach every distinct method and every meaningful variation. When several questions are essentially the same pattern and use the same steps, solve at least two representative questions in detail (prefer a straightforward one and a meaningfully varied one) and do not spend equal time repeating the identical procedure for every duplicate. Do not skip a question if it introduces a new rule, exception, data interpretation, or solution step. Explicitly indicate which repeated pattern is being demonstrated, without pretending that an unshown question was solved. ' +
          'For each selected/unique source problem, show the actual question and data from the lecture, then teach the solution step by step. Explain WHY each step is done, which rule is used, and how the numbers lead to the result, like a teacher writing on a board. Preserve source numbers, formulas, account names, dates, units, and final answers exactly. Do not replace a source problem with a generic summary. ' +
          'Do not add invented examples merely to fill time. An extra AI-created practice example is allowed only when it teaches a distinct useful variation that is not covered by source questions; label it clearly "مثال تدريبي إضافي من إنشاء AI" and never imply it came from the file. If the lecture has no practical part, do NOT invent one. ' +
          'Set scene count and narration length according to content complexity, not a preset slide count or duration ceiling. Keep closely related theory points together when that improves understanding, but give complex ideas and multi-step solutions enough screen time and separate scenes for legibility. The total duration is an estimate, not a constraint: prioritize complete, accurate teaching over hitting a number of minutes. ' +
          'For theory scenes: use a clear heading, 2-5 concise on-screen points, a meaningful visual metaphor/icon, and natural explanatory narration of sufficient depth for the concept. Do not simply read the bullets. Diagrams and arrows are allowed only when the relationship is explicit in the source. ' +
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
