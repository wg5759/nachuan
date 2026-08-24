"""实时翻译（D2）：单元 + HTTP（echo）。"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.translate import lang_name, translate

AUTH = {"Authorization": "Bearer test-key"}


class _Route:
    def __init__(self, p):  # noqa: ANN001
        self.provider = p
        self.upstream_model = "x"
        self.tier = "free"


class _Router:
    def __init__(self, p):  # noqa: ANN001
        self._p = p

    def resolve(self, m):  # noqa: ANN001
        return _Route(self._p)


class _FixedProvider:
    name = "t"

    def __init__(self, out):  # noqa: ANN001
        self.out = out
        self.seen = []

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.seen.append(req.messages[-1].content)
        return ChatCompletionResponse.from_text(
            model=req.model, text=self.out, usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        ).model_dump()


def test_lang_name():
    assert lang_name("en") == "英文"
    assert lang_name("xx") == "xx"  # 未知码原样返回


def test_translate_unit():
    prov = _FixedProvider("Hello world")
    r = asyncio.run(translate(_Router(prov), text="你好世界", target="en", model="agnes-flash"))
    assert r["translated"] == "Hello world"
    assert r["model"] == "agnes-flash" and r["target"] == "en"
    assert set(r) == {"translated", "model", "target"}
    assert "翻译成英文" in prov.seen[0]  # 提示词带了目标语种


def test_translate_can_return_private_author_evidence_to_agent_only():
    prov = _FixedProvider("Hello world")
    r = asyncio.run(
        translate(
            _Router(prov),
            text="你好世界",
            target="en",
            model="agnes-flash",
            include_author_evidence=True,
        )
    )
    assert r["translated"] == "Hello world"
    assert r["_requested_model"] == "agnes-flash"
    assert isinstance(r["_response"], dict)
    assert r["_route"] is not None


def test_translate_http_echo():
    with TestClient(app) as c:
        r = c.post("/v1/translate", headers=AUTH, json={"text": "你好", "target": "en", "model": "echo"})
        assert r.status_code == 200
        d = r.json()
        assert d["translated"] and d["model"] == "echo" and d["target"] == "en"
        assert not any(str(key).startswith("_") for key in d)


def test_translate_requires_text():
    with TestClient(app) as c:
        assert c.post("/v1/translate", headers=AUTH, json={"target": "en"}).status_code == 422
