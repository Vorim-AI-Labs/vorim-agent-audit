// FIXTURE: clean code that should NOT trigger any rules.
// Uses env vars, scoped permissions, expiring credentials.

import OpenAI from 'openai';
import { config } from 'dotenv';

config();

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const agentConfig = {
  scope: 'agent:read',
  ttl: 3600,
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
};

export { client, agentConfig };
