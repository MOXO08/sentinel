// ai.js
const openai = require('openai');
module.exports = {
  runAI: async () => {
    return await openai.chat.completions.create({ model: "gpt-4", messages: [] });
  }
}
