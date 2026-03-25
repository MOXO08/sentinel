/**
 * AI Chatbot Consumer (Adversarial Dynamic Access - String Literal)
 */
const governance = require('./governance'); 
const OpenAI = require('openai');

async function askAI(prompt) {
  const client = new OpenAI();
  const result = await client.chat.completions.create();
  
  // DYNAMIC ACCESS: String Literal
  return governance["sentinelOverride"](prompt, result);
}

module.exports = { askAI };
