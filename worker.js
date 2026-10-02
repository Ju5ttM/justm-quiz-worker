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
const BUILD_VERSION = 'v5.5-score-auth';
const GEMINI_MODEL = 'gemini-2.5-flash';
const CACHE_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

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

async function callGemini(env, parts, extraConfig) {
  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
  const apiResponse = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
    body: JSON.stringify({
      contents: [{ role: 'user', parts }],
      generationConfig: Object.assign({ responseMimeType: 'application/json' }, extraConfig || {}),
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
  const cleaned = rawText.replace(/```json|```/g, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch (e) {
    // tolerate stray text around the JSON object
    const first = cleaned.indexOf('{');
    const last = cleaned.lastIndexOf('}');
    if (first !== -1 && last > first) {
      try { return JSON.parse(cleaned.slice(first, last + 1)); } catch (e2) { /* fall through */ }
    }
    const err = new Error('رد الذكاء الاصطناعي جه بشكل غير مفهوم، جرّب تاني.');
    err.status = 502;
    throw err;
  }
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders() });

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
        return jsonResponse({ error: 'text or images required' }, 400);
      }

      const maxChars = mode === 'summary' ? 90000 : (mode === 'ask' ? 150000 : 40000);
      const trimmedText = lectureText.slice(0, maxChars);

      // Cache key: based on content + mode + params. Skip caching for 'ask' (unique per question).
      let cacheKey = null;
      if (mode !== 'ask' && env.QUIZ_KV) {
        const fingerprint = (trimmedText || '') + '|' + images.map((i) => (i.data || '').slice(0, 200)).join(',') +
          '|' + mode + '|' + difficulty + '|' + count + '|' + subject;
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
          'You are turning a university lecture into a narrated slideshow script for a student to watch and listen to. ' +
          'Break the material into 6 to 10 slides that progress logically through the content (intro/overview slide first, then one concept per slide, short wrap-up slide last). ' +
          'For each slide: "title" is a short slide heading (max ~6 words), "bullets" are 2-4 short on-screen points (each under ~10 words), ' +
          'and "narration" is what a teacher would SAY out loud for this slide — 2-4 full spoken sentences, conversational and clear, NOT just reading the bullets verbatim, explaining the point properly. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
          'JSON shape: {"slides":[{"title":"...","bullets":["...","..."],"narration":"..."}]}. ' +
          'Write in Arabic if the content is in Arabic, otherwise match the source language.\n\n' +
          `Subject: ${subject}\nTurn this lecture content into the slideshow script` +
          (images.length ? ' (read the text in the attached scanned pages):' : `:\n\n${trimmedText}`);
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
