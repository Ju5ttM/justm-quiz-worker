// Cloudflare Worker: generates a quiz from lecture text using the Gemini API
// (free tier — no permanent cost, generous daily limits).
//
// SETUP:
// 1. Get a free key at https://aistudio.google.com/apikey (Google account, no card).
// 2. wrangler secret put GEMINI_API_KEY   -> paste that key
// 3. Change ALLOWED_ORIGIN below to your app's real domain before going live.
// 4. wrangler deploy

const ALLOWED_ORIGIN = '*'; // TODO: replace with e.g. 'https://yourapp.pages.dev'
const GEMINI_MODEL = 'gemini-2.5-flash'; // free tier, ~1500 requests/day

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: corsHeaders() });
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ error: 'invalid JSON body' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    }

    const lectureText = (body.text || '').trim();
    const images = Array.isArray(body.images) ? body.images.slice(0, 15) : []; // cap pages to keep payload sane
    const subject = body.subject || 'المادة';
    const count = Math.min(Math.max(parseInt(body.count) || 10, 1), 25);

    if (!lectureText && !images.length) {
      return new Response(JSON.stringify({ error: 'text or images required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    }

    // Guard against absurdly long input (keeps well within free-tier token budget).
    const trimmedText = lectureText.slice(0, 40000);

    const instructions =
      'You are an exam-question generator for a university lecture. ' +
      'Respond with ONLY valid JSON, no markdown fences, no commentary. ' +
      'JSON shape: {"questions":[{"type":"mcq","question":"...","options":["A","B","C","D"],"correct_index":0,"explanation":"..."}]}. ' +
      'Mix mcq and short_answer types (short_answer omits options/correct_index and instead has "model_answer"). ' +
      'Base every question strictly on the given lecture content. Write questions in Arabic if the content is in Arabic, otherwise match the source language.\n\n' +
      `Subject: ${subject}\n` +
      `Generate exactly ${count} exam questions` +
      (images.length ? ' from these scanned lecture pages (read the text in the images):' : ` from this lecture content:\n\n${trimmedText}`);

    const parts = [{ text: instructions }];
    if (images.length) {
      for (const img of images) {
        if (img && img.data) {
          parts.push({ inlineData: { mimeType: img.mimeType || 'image/jpeg', data: img.data } });
        }
      }
    }

    try {
      const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
      const apiResponse = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': env.GEMINI_API_KEY,
        },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: parts }],
          generationConfig: {
            responseMimeType: 'application/json',
          },
        }),
      });

      if (!apiResponse.ok) {
        const errText = await apiResponse.text();
        return new Response(JSON.stringify({ error: 'Gemini API error', detail: errText }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', ...corsHeaders() },
        });
      }

      const data = await apiResponse.json();
      const rawText = (data.candidates && data.candidates[0] &&
        data.candidates[0].content && data.candidates[0].content.parts &&
        data.candidates[0].content.parts.map((p) => p.text || '').join('\n')) || '';

      // responseMimeType:json should guarantee clean JSON, but strip fences defensively.
      const cleaned = rawText.replace(/```json|```/g, '').trim();

      let quiz;
      try {
        quiz = JSON.parse(cleaned);
      } catch (e) {
        return new Response(JSON.stringify({ error: 'model did not return valid JSON', raw: rawText }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', ...corsHeaders() },
        });
      }

      return new Response(JSON.stringify(quiz), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'worker error', detail: String(e) }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    }
  },
};

