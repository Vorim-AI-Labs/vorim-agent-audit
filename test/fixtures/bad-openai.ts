// FIXTURE: this file intentionally contains synthetic patterns that match the
// regex shape of API keys. None of these are real credentials.

import OpenAI from 'openai';

// Should trigger: hardcoded OpenAI key (critical)
const client = new OpenAI({
  apiKey: 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp1234',
});

// Should trigger: hardcoded Anthropic key (critical)
const ANTHROPIC = 'sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrSt';

// Should trigger: hardcoded Google AI key (critical)
const GOOGLE = 'AIzaSyD-AbCdEfGhIjKlMnOpQrStUvWxYz01234';

// Should trigger: hardcoded AWS access key id (critical)
const AWS_KEY = 'AKIA2X7QDLPZNVB4HTMK';

export { client };
