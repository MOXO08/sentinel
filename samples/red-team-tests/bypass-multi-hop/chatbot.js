/**
 * AI Chatbot Consumer (Disconnected from direct signal)
 */
const { safetyHook } = require('./lib/wrapper'); // Imports generic name
const OpenAI = require('openai');

async function askAI(prompt) {
  const client = new OpenAI();
  const result = await client.chat.completions.create();
  
  // Use the wrapper
  return safetyHook(prompt, result); 
}

module.exports = { askAI };
