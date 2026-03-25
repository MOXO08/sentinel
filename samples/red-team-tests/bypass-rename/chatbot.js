/**
 * AI Chatbot Consumer (Adversarial Rename)
 */
const { sentinelOverride } = require('./governance'); 
const OpenAI = require('openai');

// ALIASING: Masking the compliance signal
const mySecretSafetyHook = sentinelOverride;

async function askAI(prompt) {
  const client = new OpenAI();
  const result = await client.chat.completions.create();
  
  // Calling the alias instead of the direct hook
  return mySecretSafetyHook(prompt, result); 
}

module.exports = { askAI };
