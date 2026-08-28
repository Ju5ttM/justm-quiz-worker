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

const ALLOWED_ORIGIN = 'https://justm.site';
const GEMINI_MODEL = 'gemini-2.5-flash';
const CACHE_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
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

async function callGemini(env, parts) {
  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
  const apiResponse = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
    body: JSON.stringify({
      contents: [{ role: 'user', parts }],
      generationConfig: { responseMimeType: 'application/json' },
    }),
  });

  if (!apiResponse.ok) {
    const errText = await apiResponse.text();
    const err = new Error('Gemini API error: ' + errText);
    err.status = apiResponse.status;
    throw err;
  }

  const data = await apiResponse.json();
  const rawText = (data.candidates && data.candidates[0] &&
    data.candidates[0].content && data.candidates[0].content.parts &&
    data.candidates[0].content.parts.map((p) => p.text || '').join('\n')) || '';
  const cleaned = rawText.replace(/```json|```/g, '').trim();
  return JSON.parse(cleaned); // let caller catch parse errors
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
      // ---- score tracking (no AI call, no cache) ----
      if (mode === 'save_score') {
        const student = slug(body.student);
        if (!student) return jsonResponse({ error: 'student name required' }, 400);
        const key = 'scores:' + student;
        const existingRaw = await env.QUIZ_KV.get(key);
        const list = existingRaw ? JSON.parse(existingRaw) : [];
        list.push({
          subject: body.subject || '',
          lecture: body.lecture || '',
          score: Number(body.score) || 0,
          total: Number(body.total) || 0,
          difficulty: body.difficulty || '',
          at: Date.now(),
        });
        await env.QUIZ_KV.put(key, JSON.stringify(list.slice(-100))); // keep last 100
        return jsonResponse({ ok: true });
      }

      if (mode === 'get_scores') {
        const student = slug(body.student);
        if (!student) return jsonResponse({ error: 'student name required' }, 400);
        const raw = await env.QUIZ_KV.get('scores:' + student);
        return jsonResponse({ scores: raw ? JSON.parse(raw) : [] });
      }

      // ---- AI-backed modes below ----
      const lectureText = (body.text || '').trim();
      const images = Array.isArray(body.images) ? body.images.slice(0, 15) : [];
      const subject = body.subject || 'المادة';
      const count = Math.min(Math.max(parseInt(body.count) || 10, 1), 25);
      const difficulty = ['easy', 'medium', 'hard'].includes(body.difficulty) ? body.difficulty : 'medium';
      const question = (body.question || '').trim();

      if (!lectureText && !images.length) {
        return jsonResponse({ error: 'text or images required' }, 400);
      }

      const maxChars = mode === 'summary' ? 90000 : 40000;
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
      const ip = request.headers.get('CF-Connecting-IP');
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
      } else if (mode === 'ask') {
        if (!question) return jsonResponse({ error: 'question is required for ask mode' }, 400);
        instructions =
          'You are a patient private tutor chatting with a student about their lecture, like a WhatsApp conversation — NOT writing an article. ' +
          'Use the given lecture content as your source of truth (you may also draw on general subject knowledge to explain better, ' +
          'but stay consistent with what the lecture says). ' +
          'STRICT rules: ' +
          '(1) Default answer length is SHORT — 2 to 5 sentences. If the question is just "what does X mean / define X", give ONLY a short plain-language definition, nothing else — no example unless asked. ' +
          '(2) Only give a worked example if the student is asking about a rule/law/problem they are confused about, or explicitly asks for an example — and even then keep it to ONE compact example, not multiple paragraphs. ' +
          '(3) NEVER use markdown formatting of any kind — no **bold**, no #headers, no bullet asterisks, no numbered-list markers. Plain conversational sentences only, like you are texting a friend. ' +
          '(4) End with a short, casual one-line offer like "قولّي لو عايز مثال" ONLY if you did not already give one — do not pad the answer with this every time. ' +
          '(5) If the student says something like "still don\'t get it" or asks for another example, give ONE different, simpler concrete example — still short. ' +
          'If the lecture genuinely does not cover what they are asking, say so honestly in one line instead of guessing. ' +
          'Respond with ONLY valid JSON, no markdown fences, no commentary. JSON shape: {"answer":"..."}. ' +
          'Answer in Arabic if the question is in Arabic, otherwise match the question language.\n\n' +
          `Subject: ${subject}\nStudent question: ${question}\n\nLecture content` +
          (images.length ? ' (read the text in the attached scanned pages):' : `:\n\n${trimmedText}`);
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
