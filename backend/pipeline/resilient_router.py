"""
resilient_router.py
-------------------
SOC-Grade LLM Routing Infrastructure for MobileGuard AI.
Handles smart payload truncation, tiered failover, and strict JSON validation.
"""

import os
import time
import json
import logging
import traceback
from typing import Dict, Any, List

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from openai import OpenAI

# Try to load your config, otherwise fall back to env vars
try:
    from backend import config
except ImportError:
    config = None

logger = logging.getLogger(__name__)

class ModelTiers:
    # High speed, massive context, native structured output support
    PRIMARY = "gemini-2.5-flash"  
    # Slower, highly reliable reasoning fallback
    FALLBACK = "gpt-4o"           

class ResilientLLMRouter:
    def __init__(self):
        # 1. Initialize Primary (Gemini)
        self.gemini_key = getattr(config, 'GEMINI_API_KEY', os.getenv("GEMINI_API_KEY"))
        if self.gemini_key:
            genai.configure(api_key=self.gemini_key)
            self.primary_client = genai.GenerativeModel(ModelTiers.PRIMARY)
        else:
            self.primary_client = None
            logger.warning("ResilientRouter: No Gemini API Key. Primary tier offline.")

        # 2. Initialize Fallback (OpenAI / OpenRouter)
        self.fallback_key = getattr(config, 'OPENAI_API_KEY', os.getenv("OPENAI_API_KEY"))
        if self.fallback_key:
            self.fallback_client = OpenAI(api_key=self.fallback_key)
        else:
            self.fallback_client = None
            logger.warning("ResilientRouter: No OpenAI API Key. Fallback tier offline.")

    def analyze_malware(self, system_prompt: str, user_prompt_template: str, decompiled_code: str, max_retries: int = 2) -> Dict[str, Any]:
        """
        The main entry point. Orchestrates truncation, routing, and validation.
        """
        code_payload = decompiled_code
        last_error = None

        for attempt in range(max_retries):
            # If we failed the first time, assume context window issues and truncate
            if attempt > 0:
                logger.info(f"Attempt {attempt + 1}: Truncating payload to ensure context fit.")
                code_payload = self._smart_truncate(code_payload)

            full_prompt = f"{system_prompt}\n\n{user_prompt_template}\n\n[DECOMPILED CODE]\n{code_payload}"

            # --- TIER 1: PRIMARY (Gemini) ---
            # --- TIER 1: PRIMARY (Gemini) ---
            if self.primary_client:
                try:
                    print(f"[ROUTER] Routing to Primary Tier: {ModelTiers.PRIMARY} (Attempt {attempt+1})")
                    # Force native JSON output and explicitly disable safety filters for malware analysis
                    response = self.primary_client.generate_content(
                        full_prompt,
                        generation_config=genai.GenerationConfig(
                            response_mime_type="application/json",
                            temperature=0.1
                        ),
                        safety_settings={
                            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                        }
                    )
                    
                    parsed_json = self._extract_and_validate_json(response.text)
                    if parsed_json:
                        return parsed_json
                    else:
                        print(f"[ROUTER] Primary Tier returned empty or invalid JSON.")
                        
                except Exception as e:
                    last_error = str(e)
                    print(f"[ROUTER ERROR] Primary Tier Failed: {str(e)}") # Force output to Docker stdout

            # --- TIER 2: FALLBACK (OpenAI/GPT-4o) ---
            if self.fallback_client:
                try:
                    logger.info(f"Routing to Fallback Tier: {ModelTiers.FALLBACK}")
                    response = self.fallback_client.chat.completions.create(
                        model=ModelTiers.FALLBACK,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": f"{user_prompt_template}\n\n{code_payload}"}
                        ],
                        response_format={ "type": "json_object" },
                        temperature=0.1
                    )
                    
                    parsed_json = self._extract_and_validate_json(response.choices[0].message.content)
                    if parsed_json:
                        return parsed_json

                except Exception as e:
                    last_error = str(e)
                    print(f"[ROUTER ERROR] Fallback Tier Failed: {str(e)}")

            # Brief backoff before truncation retry
            time.sleep(2)

        logger.error(f"All LLM routing tiers exhausted. Last error: {last_error}")
        raise RuntimeError("LLM Analysis failed across all tiers and truncation retries.")

    def _smart_truncate(self, code: str, keep_top_ratio: float = 0.4, keep_bottom_ratio: float = 0.4) -> str:
        """
        Center-out truncation. 
        Malware analysis needs class headers/imports (top) and execution tails (bottom).
        The middle of massive obfuscated files is usually boilerplate or dead code.
        """
        lines = code.splitlines()
        total_lines = len(lines)
        
        # If it's relatively small, don't truncate
        if total_lines < 3000:
            return code

        top_cutoff = int(total_lines * keep_top_ratio)
        bottom_cutoff = int(total_lines * (1 - keep_bottom_ratio))

        top_segment = "\n".join(lines[:top_cutoff])
        bottom_segment = "\n".join(lines[bottom_cutoff:])

        return f"{top_segment}\n\n... [ROUTER: {total_lines - (top_cutoff + (total_lines - bottom_cutoff))} LINES TRUNCATED FOR CONTEXT LIMIT] ...\n\n{bottom_segment}"

    def _extract_and_validate_json(self, text: str) -> Dict[str, Any]:
        """
        Ensures the response is actually valid JSON, stripping markdown if necessary.
        """
        if not text:
            return {}

        text = text.strip()
        
        # Strip markdown code blocks if the model ignored native JSON instructions
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
            
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode LLM JSON output: {e}\nRaw output preview: {text[:200]}")
            return {}