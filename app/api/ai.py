"""
POST /api/ai/chat — AI assistant endpoint for packet/capture analysis.
Sends the user's question (plus optional capture/analysis context) to the
first enabled, configured provider — local/self-hosted providers are tried
first (private), then cloud providers (Anthropic, OpenAI — pktPCAP is the
one app in the suite that supports both, matching its original Flask app).

POST /api/ai/test — validate a provider/key/model combination without
saving it first, so a user can check a key before committing it in Settings.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import aiosqlite
import httpx
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
    provider: str = ""
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


async def _call_ollama(base_url: str, model: str, system: str, message: str) -> tuple[str, int]:
    url = base_url.rstrip("/") + "/api/chat"
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": message},
        ],
    }
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    answer = data.get("message", {}).get("content", "")
    tokens = (data.get("prompt_eval_count") or 0) + (data.get("eval_count") or 0)
    return answer, tokens


async def _call_openai_compatible(base_url: str, api_key: str, model: str, system: str, message: str) -> tuple[str, int]:
    url = base_url.rstrip("/") + "/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": message},
        ],
    }
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, json=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    choice = (data.get("choices") or [{}])[0]
    answer = choice.get("message", {}).get("content", "")
    usage = data.get("usage") or {}
    tokens = (usage.get("prompt_tokens") or 0) + (usage.get("completion_tokens") or 0)
    return answer, tokens


async def _resolve_provider(db: aiosqlite.Connection) -> dict[str, Any] | None:
    """Pick the first ready provider, local/private ones before cloud.

    ai_provider_anthropic_enabled / ai_provider_openai_enabled fall back to
    this app's older single-provider `provider` radio setting the first time
    (i.e. only while the new flags have never been explicitly saved), so an
    existing configured install keeps working unchanged until the user visits
    the new Settings UI.
    """
    if (await _get_setting(db, "ai_provider_ollama_enabled")):
        base_url = await _get_setting(db, "ai_provider_ollama_base_url")
        if base_url:
            return {
                "kind": "ollama",
                "name": "Ollama",
                "base_url": base_url,
                "model": await _get_setting(db, "ai_provider_ollama_model") or "llama3.1",
            }

    for p in (await _get_setting(db, "ai_local_providers")) or []:
        if p.get("enabled") and p.get("base_url"):
            return {
                "kind": "openai_compatible",
                "name": p.get("name") or "Local AI",
                "base_url": p["base_url"],
                "api_key": p.get("api_key") or "",
                "model": p.get("model") or "",
            }

    legacy_provider = await _get_setting(db, "provider")

    anthropic_flag = await _get_setting(db, "ai_provider_anthropic_enabled")
    anthropic_enabled = (legacy_provider in (None, "anthropic")) if anthropic_flag is None else bool(anthropic_flag)
    if anthropic_enabled:
        api_key = await _get_setting(db, "anthropic_key")
        if api_key and api_key != "••••••••":
            return {
                "kind": "anthropic",
                "name": "Anthropic",
                "api_key": api_key,
                "model": await _get_setting(db, "anthropic_model") or "claude-opus-4-8",
            }

    openai_flag = await _get_setting(db, "ai_provider_openai_enabled")
    openai_enabled = (legacy_provider == "openai") if openai_flag is None else bool(openai_flag)
    if openai_enabled:
        api_key = await _get_setting(db, "openai_key")
        if api_key and api_key != "••••••••":
            return {
                "kind": "openai",
                "name": "OpenAI",
                "api_key": api_key,
                "model": await _get_setting(db, "openai_model") or "gpt-4o",
            }

    return None


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    _: CurrentUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Send a question + optional capture context to the active AI provider."""
    provider = await _resolve_provider(db)
    if not provider:
        raise HTTPException(
            status_code=503,
            detail="AI assistant not configured. Enable and configure a provider in Settings → AI Assistant.",
        )

    context_str = json.dumps(body.context, indent=2) if body.context else "(No context provided)"
    user_message = f"Capture Context:\n{context_str}\n\nQuestion: {body.question}"

    try:
        if provider["kind"] == "anthropic":
            answer, tokens = await _call_anthropic(provider["api_key"], provider["model"], SYSTEM_PROMPT, user_message, 1024)
        elif provider["kind"] == "openai":
            answer, tokens = await _call_openai(provider["api_key"], provider["model"], SYSTEM_PROMPT, user_message, 1024)
        elif provider["kind"] == "ollama":
            answer, tokens = await _call_ollama(provider["base_url"], provider["model"], SYSTEM_PROMPT, user_message)
        else:
            answer, tokens = await _call_openai_compatible(provider["base_url"], provider.get("api_key", ""), provider["model"], SYSTEM_PROMPT, user_message)

        return ChatResponse(answer=answer, provider=provider["name"], tokens_used=tokens)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"AI chat error ({provider['name']}): {e}")
        if provider["kind"] in ("anthropic", "openai") and ("authentication" in str(e).lower() or "api_key" in str(e).lower()):
            raise HTTPException(status_code=503, detail=f"Invalid {provider['name']} API key. Check Settings → AI Assistant.")
        raise HTTPException(status_code=502, detail=f"{provider['name']} error: {str(e)[:200]}")


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
