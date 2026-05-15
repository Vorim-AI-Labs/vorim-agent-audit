# FIXTURE: synthetic patterns matching the shape of credentials, not real keys.
# Tests that the shared-credentials rule fires on multi-agent LangChain setups.

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent

OPENAI_API_KEY = "loaded-from-env-elsewhere"  # variable used below


# Three agents instantiated with the same credential variable.
# Should trigger: shared-credential:multi-agent (high)

researcher = ChatOpenAI(
    model="gpt-4o",
    api_key=OPENAI_API_KEY,
    temperature=0.0,
)

writer = ChatOpenAI(
    model="gpt-4o",
    api_key=OPENAI_API_KEY,
    temperature=0.7,
)

critic = ChatOpenAI(
    model="gpt-4o-mini",
    api_key=OPENAI_API_KEY,
    temperature=0.0,
)
