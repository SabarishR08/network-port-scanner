from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request

from config import SETTINGS

try:
    import google.generativeai as genai
except Exception:  # pragma: no cover - optional runtime dependency safety
    genai = None

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a cybersecurity risk classifier for network services. "
    "You must output exactly one single line and nothing else. "
    "Required format: Risk: <Low/Medium/High> | Reason: <one sentence>. "
    "Never output markdown, bullet points, code fences, extra labels, greetings, or multiple lines. "
    "If uncertain, still choose one risk level and provide a short reason."
)


class GeminiRiskAnalyzer:
    def __init__(self, api_key: str | None, model_name: str) -> None:
        self.enabled = bool(api_key and genai)
        self.model_name = model_name
        self.model = None
        self.groq_api_key = SETTINGS.groq_api_key
        self.groq_model = SETTINGS.groq_model
        if self.enabled:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(model_name=model_name)

    @property
    def groq_enabled(self) -> bool:
        return bool(self.groq_api_key)

    def _call_groq(self, system_prompt: str, user_prompt: str) -> str:
        if not self.groq_enabled:
            return ""

        payload = {
            "model": self.groq_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        req = urllib.request.Request(
            url="https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "PowerScan/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(body)
            return (
                parsed.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )
        except urllib.error.HTTPError as exc:
            raw = ""
            try:
                raw = exc.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            logger.warning("Groq risk analysis failed: %s | body=%s", exc, raw[:400])
            return ""
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("Groq risk analysis failed: %s", exc)
            return ""

    def analyze_port_risk(self, port: int, service: str, banner: str) -> str:
        user_prompt = (
            f"Port: {port}\n"
            f"Service: {service or 'Unknown'}\n"
            f"Banner/Version: {banner or 'Unknown'}\n\n"
            "Return exactly one line in this exact template:\n"
            "Risk: <Low/Medium/High> | Reason: <one-line explanation>\n"
            "Do not add any extra text before or after."
        )

        if self.enabled and self.model:
            try:
                response = self.model.generate_content([SYSTEM_PROMPT, user_prompt])
                raw_text = (getattr(response, "text", "") or "").strip()
                one_line = " ".join(raw_text.split())
                match = re.match(r"^Risk:\s*(Low|Medium|High)\s*\|\s*Reason:\s*(.+)$", one_line, flags=re.IGNORECASE)
                if match:
                    risk = match.group(1).capitalize()
                    reason = match.group(2).strip()
                    return f"Risk: {risk} | Reason: {reason}"
            except Exception as exc:  # pragma: no cover - network/API runtime
                logger.warning("Gemini risk analysis failed: %s", exc)

        groq_text = self._call_groq(SYSTEM_PROMPT, user_prompt)
        if groq_text:
            one_line = " ".join(groq_text.split())
            match = re.match(r"^Risk:\s*(Low|Medium|High)\s*\|\s*Reason:\s*(.+)$", one_line, flags=re.IGNORECASE)
            if match:
                risk = match.group(1).capitalize()
                reason = match.group(2).strip()
                return f"Risk: {risk} | Reason: {reason}"

        return "Risk: Unknown | Reason: Unable to analyze"

    def _parse_batch_output(self, raw_text: str, entries: list[dict], source: str) -> dict[int, dict]:
        parsed: dict[int, dict] = {}
        for raw_line in (raw_text or "").splitlines():
            line = " ".join(raw_line.strip().split())
            match = re.match(
                r"^(\d+)\|Risk:\s*(Low|Medium|High)\s*\|\s*Reason:\s*(.+)$",
                line,
                flags=re.IGNORECASE,
            )
            if not match:
                continue
            port = int(match.group(1))
            risk = match.group(2).capitalize()
            reason = match.group(3).strip() or "Unable to analyze"
            parsed[port] = {"line": f"Risk: {risk} | Reason: {reason}", "source": source}

        for item in entries:
            port = int(item["port"])
            if port not in parsed:
                parsed[port] = {"line": "Risk: Unknown | Reason: Unable to analyze", "source": "fallback"}
        return parsed

    def analyze_ports_risk_with_source(self, entries: list[dict]) -> dict[int, dict]:
        if not entries:
            return {}

        lines = []
        for item in entries:
            lines.append(
                f"{int(item['port'])}|{item.get('service', 'Unknown') or 'Unknown'}|{item.get('banner', 'Unknown') or 'Unknown'}"
            )

        user_prompt = (
            "Classify all ports below in one response.\n"
            "Input format per line: <port>|<service>|<banner>.\n"
            "Output format must be exactly one line per input in the same order using this exact template:\n"
            "<port>|Risk: <Low/Medium/High> | Reason: <one-line explanation>\n"
            "No markdown. No bullets. No extra text. No blank lines.\n\n"
            "Ports:\n"
            + "\n".join(lines)
        )

        fallback = {
            int(item["port"]): {"line": "Risk: Unknown | Reason: Unable to analyze", "source": "fallback"}
            for item in entries
        }
        if self.enabled and self.model:
            try:
                response = self.model.generate_content([SYSTEM_PROMPT, user_prompt])
                raw_text = (getattr(response, "text", "") or "").strip()
                parsed = self._parse_batch_output(raw_text, entries, "gemini")
                if any(value["source"] != "fallback" for value in parsed.values()):
                    return parsed
            except Exception as exc:  # pragma: no cover - network/API runtime
                logger.warning("Gemini batch risk analysis failed: %s", exc)

        groq_text = self._call_groq(SYSTEM_PROMPT, user_prompt)
        if groq_text:
            parsed = self._parse_batch_output(groq_text, entries, "groq")
            if any(value["source"] != "fallback" for value in parsed.values()):
                return parsed

        return fallback

    def analyze_ports_risk(self, entries: list[dict]) -> dict[int, str]:
        with_source = self.analyze_ports_risk_with_source(entries)
        return {port: payload["line"] for port, payload in with_source.items()}


risk_analyzer = GeminiRiskAnalyzer(SETTINGS.gemini_api_key, SETTINGS.gemini_model)


def analyze_port_risk(port: int, service: str, banner: str) -> str:
    return risk_analyzer.analyze_port_risk(port, service, banner)


def analyze_ports_risk(entries: list[dict]) -> dict[int, str]:
    return risk_analyzer.analyze_ports_risk(entries)


def analyze_ports_risk_with_source(entries: list[dict]) -> dict[int, dict]:
    return risk_analyzer.analyze_ports_risk_with_source(entries)
