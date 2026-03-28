// ai_module_2.js
const anthropic = require('anthropic');
const msg = await anthropic.messages.create({ model: "claude-3", messages: [] });
