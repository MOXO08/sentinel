/**
 * AI Chatbot Consumer (Connected Transitive)
 */
const { technicalSentinelHook } = require('./governance'); 
const OpenAI = require('openai');

async function askAI(prompt) {
  const client = new OpenAI();
  const result = await client.chat.completions.create();
  
  return technicalSentinelHook(prompt, result); 
}

module.exports = { askAI };
