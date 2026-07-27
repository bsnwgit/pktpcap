"""
POST /api/ai/chat — AI assistant endpoint for packet/capture analysis.
Sends the user's question (plus optional capture/analysis context) to
whichever provider is configured (Anthropic or OpenAI — pktPCAP is the one
app in the suite that supports both, matching its original Flask app).

POST /api/ai/test — validate a provider/key/model combination without
saving it first, so a user can check a key before committing it in Settings.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import get_db
from app.dependencies import CurrentUser

router = APIRouter()
log = logging.getLogger("pktpcap.ai")

SYSTEM_PROMPT = """You are a network operations assistant integrated into pktPCAP, a
packet capture and analysis tool. Your role is to help network engineers interpret
packet captures, flows, protocol breakdowns, and anomaly/threat findings, and provide
actionable troubleshooting guidance.

You may receive structured capture context (protocol summary, top talkers, flow
counts, anomalies, DNS/TCP/UDP stats) alongside the user's question. Analyze the
data and provide clear, concise answers.

Guidelines:
- Be specific and reference the actual data provided when relevant
- Flag anomalies, suspicious traffic patterns, or misconfigurations you notice
- Suggest investigation steps when appropriate
- Keep responses focused — users are busy network engineers
- Use plain text; avoid markdown headers in responses (inline bold is fine)"""


class ChatRequest(BaseModel):
    question: str
    context: dict[str, Any] = {}  # Optional capture/analysis context from the current view


class ChatResponse(BaseModel):
    answer: str
    tokens_used: int = 0


class TestRequest(BaseModel):
    provider: str
    api_key: str
    model: str | None = None


async def _get_setting(db: aiosqlite.Connection, key: str) -> Any:
    async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as cur:
        row = await cur.fetchone()
    return json.loads(row[0]) if row else None


async def _call_anthropic(api_key: str, model: str, system: str, message: str, max_tokens: int) -> tuple[str, int]:
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=api_key)
    response = await client.messages.create(
        model=model, max_tokens=max_tokens, system=system,
        messages=[{"role": "user", "content": message}],
    )
    answer = response.content[0].text if response.content else ""
    tokens = response.usage.input_tokens + response.usage.output_tokens
    return answer, tokens


async def _call_openai(api_key: str, model: str, system: str, message: str, max_tokens: int) -> tuple[str, int]:
    import openai
    client = openai.AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model, max_tokens=max_tokens,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": message}],
    )
    answer = response.choices[0].message.content or ""
    tokens = (response.usage.total_tokens if response.usage else 0) or 0
    return answer, tokens


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    _: CurrentUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Send a question + optional capture context to the configured AI provider."""
    provider = await _get_setting(db, "provider") or "anthropic"

    context_str = json.dumps(body.context, indent=2) if body.context else "(No context provided)"
    user_message = f"Capture Context:\n{context_str}\n\nQuestion: {body.question}"

    try:
        if provider == "anthropic":
            api_key = await _get_setting(db, "anthropic_key")
            if not api_key:
                raise HTTPException(
                    status_code=503,
                    detail="AI assistant not configured. Add your Anthropic API key in Settings → AI Assistant.",
                )
            model = await _get_setting(db, "anthropic_model") or "claude-opus-4-8"
            answer, tokens = await _call_anthropic(api_key, model, SYSTEM_PROMPT, user_message, 1024)
        elif provider == "openai":
            api_key = await _get_setting(db, "openai_key")
            if not api_key:
                raise HTTPException(
                    status_code=503,
                    detail="AI assistant not configured. Add your OpenAI API key in Settings → AI Assistant.",
                )
            model = await _get_setting(db, "openai_model") or "gpt-4o"
            answer, tokens = await _call_openai(api_key, model, SYSTEM_PROMPT, user_message, 1024)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown AI provider: {provider}")

        return ChatResponse(answer=answer, tokens_used=tokens)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"AI chat error: {e}")
        if "authentication" in str(e).lower() or "api_key" in str(e).lower():
            raise HTTPException(status_code=503, detail=f"Invalid {provider} API key. Check Settings → AI Assistant.")
        raise HTTPException(status_code=502, detail=f"AI service error: {str(e)[:200]}")


@router.post("/test")
async def test_ai_key(body: TestRequest, _: CurrentUser) -> dict:
    """Exercise a provider/key/model combination with a trivial prompt, without saving it."""
    if not body.api_key:
        return {"ok": False, "error": f"No {body.provider} key provided"}

    try:
        if body.provider == "anthropic":
            model = body.model or "claude-opus-4-8"
            answer, _tokens = await _call_anthropic(body.api_key, model, "", "Say PONG", 20)
            return {"ok": True, "reply": answer}
        elif body.provider == "openai":
            model = body.model or "gpt-4o"
            answer, _tokens = await _call_openai(body.api_key, model, "", "Say PONG", 20)
            return {"ok": True, "reply": answer}
        else:
            return {"ok": False, "error": f"Unknown provider: {body.provider}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
