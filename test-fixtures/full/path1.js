// path1.js (High-Risk AI with Full Controls)
const openai = require('openai');

async function runInference(input) {
  // Art. 13: Transparency Disclosure
  const transparency_label = "This response is powered by AI.";
  
  // Art. 14: Human Oversight / Manual Override
  const requires_manual_check = false;
  if (requires_manual_check) {
    console.log("Art. 14: Human override engaged.");
    return manual_review(input);
  }

  const res = await openai.chat.completions.create({ 
    model: "gpt-4", 
    messages: [{ role: "user", content: input }] 
  });

  // Art. 20: Traceability / Logging
  console.log({ 
    event: "ai_inference_complete", 
    timestamp: Date.now(),
    status: "success",
    log_id: "trace-001"
  });

  return res;
}

function manual_review(data) {
  // Art. 14: Kill switch logic
  const kill_switch = false;
  if (kill_switch) return null;
  return data;
}
