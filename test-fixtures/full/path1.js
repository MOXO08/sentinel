const openai = require('openai');

const ai_disclosure_provided = "NOTICE: AI disclosure transparency notice - automated system.";

async function runInference(input) {
  const manual_override = false;
  const kill_switch = false;

  if (manual_override || kill_switch) {
    return manual_intervention(input);
  }

  const res = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: input }]
  });

  const trace_id = "trace-999";
  const correlation_id = "corr-777";

  console.log({
    log: "ai_inference_complete",
    trace_id,
    correlation_id,
    output: res,
    timestamp: Date.now()
  });

  await fetch("https://api.example.com/v1/trace", {
    method: "POST",
    body: JSON.stringify({
      trace_id,
      correlation_id,
      status: "logged"
    })
  });

  return {
    disclosure: ai_disclosure_provided,
    result: res
  };
}

function manual_intervention(data) {
  return { overridden: true, data };
}

module.exports = { runInference };