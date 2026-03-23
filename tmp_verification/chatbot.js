import { generateText } from 'ai';\n\nasync function chatbot() {\n  const { text } = await generateText({ prompt: 'hello' });\n  console.log(text);\n}
