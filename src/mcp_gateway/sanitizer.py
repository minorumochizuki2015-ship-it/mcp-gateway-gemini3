"""Context Sanitizer - SA-002対応.

間接プロンプトインジェクション（Indirect Prompt Injection）対策。
外部データソースからのコンテンツをサニタイズし、安全なコンテキストを生成する。

検証項目:
- SAN-001: 危険パターンの検出と除去
- SAN-002: 多層サニタイズ（レベル別）
- SAN-003: サニタイズ結果の追跡（監査証跡）
"""

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SanitizationLevel(str, Enum):
    """サニタイズレベル."""

    MINIMAL = "minimal"  # 明らかな攻撃パターンのみ
    STANDARD = "standard"  # 標準的なサニタイズ
    STRICT = "strict"  # 厳格なサニタイズ
    PARANOID = "paranoid"  # 最も厳格（誤検出覚悟）


class ThreatType(str, Enum):
    """脅威タイプ."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    UNKNOWN = "unknown"


class DetectedThreat(BaseModel):
    """検出された脅威."""

    threat_type: ThreatType = Field(..., description="脅威タイプ")
    pattern: str = Field(..., description="検出パターン")
    position: int = Field(default=0, description="検出位置")
    severity: str = Field(default="medium", description="深刻度")
    context: str = Field(default="", description="周辺コンテキスト")


class SanitizationResult(BaseModel):
    """サニタイズ結果."""

    original_text: str = Field(..., description="元テキスト")
    sanitized_text: str = Field(..., description="サニタイズ済みテキスト")
    level: SanitizationLevel = Field(..., description="適用レベル")
    threats_detected: list[DetectedThreat] = Field(
        default_factory=list,
        description="検出された脅威",
    )
    is_safe: bool = Field(default=True, description="安全判定")
    modifications_count: int = Field(default=0, description="変更箇所数")
    sanitized_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="サニタイズ日時",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def threat_count(self) -> int:
        """脅威検出数."""
        return len(self.threats_detected)

    @property
    def high_severity_count(self) -> int:
        """高深刻度の脅威数."""
        return sum(1 for t in self.threats_detected if t.severity == "high")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "original_text": "Hello world",
                "sanitized_text": "Hello world",
                "level": "standard",
                "is_safe": True,
            }
        }
    )


# パターン定義
PROMPT_INJECTION_PATTERNS = [
    # 直接的な指示改ざん
    (r"ignore\s+(previous|all|above|prior)?\s*instructions?", "high"),
    (r"disregard\s+(previous|all|everything)", "high"),
    (r"forget\s+(everything|all|previous)", "high"),
    (r"(override|bypass)\s+(instructions?|rules?|safety)", "high"),
    # ロール変更
    (r"you\s+are\s+(now|actually)", "high"),
    (r"act\s+as\s+(if|a|an)", "medium"),
    (r"pretend\s+(to\s+be|you\s+are)", "medium"),
    (r"roleplay\s+as", "medium"),
    # システム情報抽出
    (r"(reveal|show|display|print)\s+(your|the)\s+(instructions?|prompt|system)", "high"),
    (r"what\s+(are|is)\s+your\s+(instructions?|system\s+prompt)", "medium"),
    # デリミタ攻撃
    (r"\[/?system\]", "high"),
    (r"</?system>", "high"),
    (r"```\s*(system|admin|root)", "medium"),
    # データ抽出
    (r"(list|show|reveal)\s+(all|every)\s+(users?|data|files?)", "medium"),
]

JAILBREAK_PATTERNS = [
    (r"DAN\s*mode", "high"),
    (r"Developer\s*Mode", "high"),
    (r"jailbreak", "high"),
    (r"unrestricted\s*mode", "high"),
    (r"(no|without)\s*(restrictions?|limits?|rules?)", "medium"),
]

XSS_PATTERNS = [
    (r"<script[^>]*>", "high"),
    (r"</script>", "high"),
    (r"javascript:", "high"),
    (r"on(load|error|click|mouse\w+)\s*=", "medium"),
    (r"<iframe[^>]*>", "medium"),
]

COMMAND_INJECTION_PATTERNS = [
    (r";\s*(rm|del|format|shutdown)", "high"),
    (r"\|\s*(bash|sh|cmd|powershell)", "high"),
    (r"`[^`]+`", "medium"),
    (r"\$\([^)]+\)", "medium"),
]


class ContextSanitizer:
    """コンテキストサニタイザー.

    外部データソースからのコンテンツをサニタイズし、
    間接プロンプトインジェクションを防止する。

    Example:
        sanitizer = ContextSanitizer(level=SanitizationLevel.STANDARD)
        result = sanitizer.sanitize("User input: ignore previous instructions")
        if result.is_safe:
            process(result.sanitized_text)
    """

    def __init__(
        self,
        level: SanitizationLevel = SanitizationLevel.STANDARD,
        custom_patterns: list[tuple[str, str]] | None = None,
    ):
        """ContextSanitizerを初期化.

        Args:
            level: サニタイズレベル
            custom_patterns: カスタムパターン [(pattern, severity), ...]
        """
        self.level = level
        self.custom_patterns = custom_patterns or []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """パターンをコンパイル."""
        self._patterns: dict[ThreatType, list[tuple[re.Pattern[str], str]]] = {
            ThreatType.PROMPT_INJECTION: [
                (re.compile(p, re.IGNORECASE), s) for p, s in PROMPT_INJECTION_PATTERNS
            ],
            ThreatType.JAILBREAK: [
                (re.compile(p, re.IGNORECASE), s) for p, s in JAILBREAK_PATTERNS
            ],
            ThreatType.XSS: [(re.compile(p, re.IGNORECASE), s) for p, s in XSS_PATTERNS],
            ThreatType.COMMAND_INJECTION: [
                (re.compile(p, re.IGNORECASE), s) for p, s in COMMAND_INJECTION_PATTERNS
            ],
        }
        # カスタムパターン追加
        if self.custom_patterns:
            self._patterns[ThreatType.UNKNOWN] = [
                (re.compile(p, re.IGNORECASE), s) for p, s in self.custom_patterns
            ]

    def sanitize(self, text: str) -> SanitizationResult:
        """テキストをサニタイズ.

        Args:
            text: サニタイズ対象テキスト

        Returns:
            SanitizationResult: サニタイズ結果
        """
        if not text:
            return SanitizationResult(
                original_text="",
                sanitized_text="",
                level=self.level,
                is_safe=True,
            )

        threats: list[DetectedThreat] = []
        sanitized = text
        modifications = 0

        # レベルに応じたパターンを適用
        pattern_types = self._get_pattern_types_for_level()

        for threat_type in pattern_types:
            if threat_type not in self._patterns:
                continue
            for pattern, severity in self._patterns[threat_type]:
                for match in pattern.finditer(text):
                    threats.append(
                        DetectedThreat(
                            threat_type=threat_type,
                            pattern=match.group(),
                            position=match.start(),
                            severity=severity,
                            context=text[max(0, match.start() - 20) : match.end() + 20],
                        )
                    )
                # パターンを置換
                new_sanitized = pattern.sub("[REDACTED]", sanitized)
                if new_sanitized != sanitized:
                    modifications += sanitized.count("[REDACTED]") - new_sanitized.count(
                        "[REDACTED]"
                    )
                    modifications = max(modifications, 1)
                sanitized = new_sanitized

        # 制御文字の除去
        sanitized = self._remove_control_chars(sanitized)

        # 安全性判定
        is_safe = self._evaluate_safety(threats)

        return SanitizationResult(
            original_text=text,
            sanitized_text=sanitized,
            level=self.level,
            threats_detected=threats,
            is_safe=is_safe,
            modifications_count=modifications,
        )

    def _get_pattern_types_for_level(self) -> list[ThreatType]:
        """レベルに応じたパターンタイプを取得."""
        if self.level == SanitizationLevel.MINIMAL:
            return [ThreatType.PROMPT_INJECTION]
        elif self.level == SanitizationLevel.STANDARD:
            return [
                ThreatType.PROMPT_INJECTION,
                ThreatType.JAILBREAK,
                ThreatType.XSS,
                ThreatType.UNKNOWN,  # カスタムパターン対応
            ]
        elif self.level == SanitizationLevel.STRICT:
            return [
                ThreatType.PROMPT_INJECTION,
                ThreatType.JAILBREAK,
                ThreatType.XSS,
                ThreatType.COMMAND_INJECTION,
                ThreatType.UNKNOWN,  # カスタムパターン対応
            ]
        else:  # PARANOID
            return list(ThreatType)

    def _remove_control_chars(self, text: str) -> str:
        """制御文字を除去."""
        # タブと改行は許可、その他の制御文字は除去
        return "".join(char for char in text if ord(char) >= 32 or char in "\n\t\r")

    def _evaluate_safety(self, threats: list[DetectedThreat]) -> bool:
        """安全性を評価."""
        if not threats:
            return True

        # 高深刻度の脅威があれば unsafe
        if any(t.severity == "high" for t in threats):
            return False

        # レベルに応じた判定
        if self.level == SanitizationLevel.PARANOID:
            return len(threats) == 0
        elif self.level == SanitizationLevel.STRICT:
            return len(threats) <= 1 and all(t.severity == "low" for t in threats)
        elif self.level == SanitizationLevel.STANDARD:
            return not any(t.severity == "high" for t in threats)
        else:  # MINIMAL
            return True

    def batch_sanitize(self, texts: list[str]) -> list[SanitizationResult]:
        """複数テキストを一括サニタイズ.

        Args:
            texts: サニタイズ対象テキストリスト

        Returns:
            list[SanitizationResult]: サニタイズ結果リスト
        """
        return [self.sanitize(text) for text in texts]

    def is_safe(self, text: str) -> bool:
        """テキストが安全かどうかを判定（簡易版）.

        Args:
            text: 判定対象テキスト

        Returns:
            bool: 安全ならTrue
        """
        return self.sanitize(text).is_safe
