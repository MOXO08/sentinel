import { generateText } from 'ai'; // SHOULD BE 'import'

async function test() {
  const result = await generateText({ model: 'gpt-4' }); // SHOULD BE 'invocation'
  
  const config = {
    method: "generateText", // SHOULD BE 'literal'
    note: 'This is a generateText mention' // SHOULD BE 'literal'
  };
}

// Another call
streamText(); // SHOULD BE 'invocation'
