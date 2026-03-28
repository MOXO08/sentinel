// main.js
const { runAI } = require('./ai.js');
runAI().then(res => console.log('AI response received'));

// dead_oversight.js
function manualOverride() {
  console.log("Art. 14: Manual override performed");
  return true;
}
// NEVER IMPORTED, NEVER CALLED

// hidden_logic.js
function killSwitch() {
  const meta = { event: "kill_switch", article: "Art. 14" };
  console.log(meta);
}
// NEVER IMPORTED, NEVER CALLED
