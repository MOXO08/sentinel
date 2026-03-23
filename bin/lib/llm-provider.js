/**
 * LLM Provider Abstraction for Sentinel Phase 11.
 * Supports OpenAI and Anthropic with silent fail and timeouts.
 */
const https = require('https');

/**
 * Calls the configured LLM provider.
 * @param {string} systemPrompt 
 * @param {string} userPrompt 
 * @returns {Promise<string|null>}
 */
async function callLLM(systemPrompt, userPrompt) {
  const provider = process.env.SENTINEL_LLM_PROVIDER || 'none';
  const apiKey = process.env.SENTINEL_LLM_API_KEY;
  const model = process.env.SENTINEL_LLM_MODEL || 
                (provider === 'openai' ? 'gpt-4o-mini' : 
                 provider === 'groq' ? 'llama-3.3-70b-versatile' : 
                 'claude-haiku-4-5-20251001');

  if (provider === 'none' || !apiKey) return null;

  return new Promise((resolve) => {
    let options, body;

    if (provider === 'openai' || provider === 'groq') {
      options = {
        hostname: provider === 'openai' ? 'api.openai.com' : 'api.groq.com',
        port: 443,
        path: provider === 'openai' ? '/v1/chat/completions' : '/openai/v1/chat/completions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        timeout: 30000
      };
      body = JSON.stringify({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        max_tokens: 1000,
        temperature: 0
      });
    } else if (provider === 'anthropic') {
      options = {
        hostname: 'api.anthropic.com',
        port: 443,
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        timeout: 30000
      };
      body = JSON.stringify({
        model,
        max_tokens: 1000,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }]
      });
    } else {
      return resolve(null);
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (provider === 'openai' || provider === 'groq') {
            resolve(json.choices?.[0]?.message?.content || null);
          } else {
            resolve(json.content?.[0]?.text || null);
          }
        } catch (e) {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.write(body);
    req.end();
  });
}

module.exports = { callLLM };
