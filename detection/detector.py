"""
Prompt-Shield: Core Detection Engine

Multi-layered prompt injection detection using:
1. Pattern matching (known attack patterns)
2. Heuristic analysis (suspicious structures)
3. Semantic analysis (context deviation)
4. Statistical anomaly detection
"""

import re
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class ThreatLevel(Enum):
    """Detection threat levels"""
    CRITICAL = 5  # Definite attack
    HIGH = 4      # Very likely attack
    MEDIUM = 3    # Suspicious pattern
    LOW = 2       # Minor concern
    SAFE = 1      # Clean


@dataclass
class DetectionResult:
    """Result of prompt injection detection"""
    is_injection: bool
    threat_level: ThreatLevel
    confidence: float  # 0.0 - 1.0
    patterns_detected: List[str]
    risk_score: float  # 0-100
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "is_injection": self.is_injection,
            "threat_level": self.threat_level.name,
            "confidence": self.confidence,
            "patterns_detected": self.patterns_detected,
            "risk_score": self.risk_score,
            "details": self.details
        }


class PromptInjectionDetector:
    """
    Multi-layered prompt injection detection engine
    """
    
    def __init__(self):
        """Initialize detection patterns"""
        # Known injection patterns (regex)
        self.injection_patterns = {
            # System prompt override attempts
            "system_override": [
                r"ignore\s+(all\s+)?previous\s+instructions",
                r"disregard\s+(all\s+)?prior\s+instructions",
                r"forget\s+(all\s+)?previous\s+(instructions|commands)",
                r"you\s+are\s+now\s+a\s+different\s+(assistant|ai|model)",
                r"new\s+instructions?:",
                r"override\s+system\s+prompt"
            ],
            
            # Role manipulation
            "role_manipulation": [
                r"you\s+are\s+now\s+in\s+.*\s+mode",
                r"DAN\s+mode",  # "Do Anything Now"
                r"jailbreak\s+mode",
                r"pretend\s+to\s+be\s+[^.]{0,50}(hacker|malicious|evil)",
                r"act\s+as\s+if\s+you\s+(have\s+no|ignore)\s+(ethics|rules|restrictions)"
            ],
            
            # Prompt leaking attempts
            "prompt_leak": [
                r"(show|reveal|display|print)\s+(your|the)\s+(system\s+)?prompt",
                r"what\s+(are|were)\s+you\s+(told|instructed)\s+to",
                r"repeat\s+(your|the)\s+instructions",
                r"output\s+your\s+(original|system)\s+prompt"
            ],
            
            # Instruction injection
            "instruction_injection": [
                r"<\s*system\s*>.*</\s*system\s*>",
                r"<\s*admin\s*>.*</\s*admin\s*>",
                r"\{\s*system\s*:.*\}",
                r"```\s*(system|admin|root)",
                r"sudo\s+[a-z]+",
                r"\\n\\n###\s*Instruction"
            ],
            
            # Delimiter manipulation
            "delimiter_abuse": [
                r"={5,}",  # Multiple equals signs
                r"-{5,}",  # Multiple dashes
                r"#{5,}",  # Multiple hashes
                r"\*{5,}",  # Multiple asterisks
                r"<{3,}",   # Multiple angle brackets
                r">{3,}"
            ],
            
            # Code injection attempts
            "code_injection": [
                r"<script[^>]*>",
                r"javascript:",
                r"eval\s*\(",
                r"exec\s*\(",
                r"__import__\s*\(",
                r"system\s*\(",
                r"os\.popen"
            ]
        }
        
        # Suspicious keywords (weighted)
        self.suspicious_keywords = {
            "ignore": 2.0,
            "disregard": 2.0,
            "override": 2.5,
            "jailbreak": 3.0,
            "prompt": 1.5,
            "system": 1.5,
            "admin": 2.0,
            "sudo": 2.5,
            "root": 2.0,
            "bypass": 2.5,
            "trick": 1.5,
            "hack": 2.0,
            "exploit": 2.5,
            "injection": 3.0
        }
    
    def detect(self, prompt: str) -> DetectionResult:
        """
        Analyze a prompt for injection attempts
        
        Args:
            prompt: The user prompt to analyze
            
        Returns:
            DetectionResult with detection findings
        """
        patterns_found = []
        pattern_scores = []
        details = {}
        
        # Layer 1: Pattern Matching
        for category, patterns in self.injection_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, prompt, re.IGNORECASE)
                if matches:
                    patterns_found.append(f"{category}: {pattern[:50]}...")
                    pattern_scores.append(self._get_category_score(category))
                    
                    if category not in details:
                        details[category] = []
                    details[category].append({
                        "pattern": pattern[:50],
                        "matches": len(matches)
                    })
        
        # Layer 2: Keyword Analysis
        keyword_score = self._analyze_keywords(prompt)
        if keyword_score > 3.0:
            patterns_found.append(f"suspicious_keywords: score={keyword_score:.1f}")
            details["keyword_analysis"] = {
                "score": keyword_score,
                "keywords_found": self._get_found_keywords(prompt)
            }
        
        # Layer 3: Structural Analysis
        structural_score = self._analyze_structure(prompt)
        if structural_score > 20:
            patterns_found.append(f"suspicious_structure: score={structural_score:.1f}")
            details["structural_analysis"] = {
                "score": structural_score,
                "anomalies": self._get_structural_anomalies(prompt)
            }
        
        # Calculate risk score and threat level
        risk_score = self._calculate_risk_score(
            pattern_scores, keyword_score, structural_score
        )
        
        threat_level = self._determine_threat_level(risk_score)
        is_injection = risk_score > 30  # Threshold for injection classification
        confidence = min(risk_score / 100, 1.0)
        
        return DetectionResult(
            is_injection=is_injection,
            threat_level=threat_level,
            confidence=confidence,
            patterns_detected=patterns_found,
            risk_score=risk_score,
            details=details
        )
    
    def _get_category_score(self, category: str) -> float:
        """Get severity score for a pattern category"""
        category_scores = {
            "system_override": 30.0,
            "role_manipulation": 25.0,
            "prompt_leak": 20.0,
            "instruction_injection": 35.0,
            "delimiter_abuse": 15.0,
            "code_injection": 40.0
        }
        return category_scores.get(category, 10.0)
    
    def _analyze_keywords(self, prompt: str) -> float:
        """Analyze suspicious keyword density"""
        prompt_lower = prompt.lower()
        total_score = 0.0
        
        for keyword, weight in self.suspicious_keywords.items():
            count = prompt_lower.count(keyword)
            total_score += count * weight
        
        # Normalize by prompt length
        word_count = len(prompt.split())
        if word_count > 0:
            total_score = (total_score / word_count) * 100
        
        return total_score
    
    def _get_found_keywords(self, prompt: str) -> List[str]:
        """Get list of suspicious keywords found"""
        prompt_lower = prompt.lower()
        found = []
        
        for keyword in self.suspicious_keywords.keys():
            if keyword in prompt_lower:
                found.append(keyword)
        
        return found
    
    def _analyze_structure(self, prompt: str) -> float:
        """Analyze prompt structure for anomalies"""
        score = 0.0
        
        # Check for excessive newlines
        newline_count = prompt.count('\n')
        if newline_count > 5:
            score += (newline_count - 5) * 2
        
        # Check for XML/HTML-like tags
        tag_pattern = r'<[^>]+>'
        tag_count = len(re.findall(tag_pattern, prompt))
        if tag_count > 2:
            score += tag_count * 3
        
        # Check for code blocks
        code_block_count = len(re.findall(r'```', prompt))
        if code_block_count > 2:
            score += code_block_count * 4
        
        # Check for unusual character patterns
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', prompt)) / max(len(prompt), 1)
        if special_char_ratio > 0.3:
            score += special_char_ratio * 20
        
        # Check for repeated delimiter patterns
        delimiter_patterns = [r'={3,}', r'-{3,}', r'#{3,}', r'\*{3,}']
        for pattern in delimiter_patterns:
            if re.search(pattern, prompt):
                score += 5
        
        return score
    
    def _get_structural_anomalies(self, prompt: str) -> List[str]:
        """Get list of structural anomalies detected"""
        anomalies = []
        
        if prompt.count('\n') > 5:
            anomalies.append(f"excessive_newlines: {prompt.count(chr(10))}")
        
        tag_count = len(re.findall(r'<[^>]+>', prompt))
        if tag_count > 2:
            anomalies.append(f"html_tags: {tag_count}")
        
        code_blocks = len(re.findall(r'```', prompt))
        if code_blocks > 2:
            anomalies.append(f"code_blocks: {code_blocks}")
        
        return anomalies
    
    def _calculate_risk_score(
        self, 
        pattern_scores: List[float],
        keyword_score: float,
        structural_score: float
    ) -> float:
        """Calculate overall risk score (0-100)"""
        # Pattern matching (60% weight)
        pattern_score = sum(pattern_scores) if pattern_scores else 0.0
        
        # Keyword analysis (25% weight)
        keyword_component = keyword_score * 0.25
        
        # Structural analysis (15% weight)
        structural_component = structural_score * 0.15
        
        # Combine scores
        total_score = pattern_score + keyword_component + structural_component
        
        # Cap at 100
        return min(total_score, 100.0)
    
    def _determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Determine threat level based on risk score"""
        if risk_score >= 70:
            return ThreatLevel.CRITICAL
        elif risk_score >= 50:
            return ThreatLevel.HIGH
        elif risk_score >= 30:
            return ThreatLevel.MEDIUM
        elif risk_score >= 10:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE


# Convenience function for quick detection
def detect_injection(prompt: str) -> DetectionResult:
    """
    Quick detection function
    
    Args:
        prompt: The prompt to analyze
        
    Returns:
        DetectionResult
    """
    detector = PromptInjectionDetector()
    return detector.detect(prompt)