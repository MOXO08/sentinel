// ai_module_1.js
const openai = require('openai');
const res = await openai.chat.completions.create({ model: "gpt-4", messages: [] });
