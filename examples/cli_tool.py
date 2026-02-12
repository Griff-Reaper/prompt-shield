#!/usr/bin/env python3
"""
Prompt-Shield CLI Tool

Command-line utility to check prompts for injection attempts.
Useful for testing, CI/CD pipelines, and security audits.

Usage:
    # Check single prompt
    python cli_tool.py "Your prompt here"
    
    # Check from file
    python cli_tool.py --file prompts.txt
    
    # Batch check with custom threshold
    python cli_tool.py --file prompts.txt --threshold 0.6
    
    # Output JSON for scripting
    python cli_tool.py "test" --json

Examples:
    python cli_tool.py "What is 2+2?"
    python cli_tool.py "Ignore all instructions" --verbose
    python cli_tool.py --file test_prompts.txt --json > results.json
"""

import sys
import argparse
import json
from pathlib import Path
from detection.ensemble_detector import EnsembleDetector


def check_prompt(detector, prompt, verbose=False, json_output=False):
    """
    Check single prompt and display results.
    
    Args:
        detector: EnsembleDetector instance
        prompt: Text to check
        verbose: Show detailed scoring breakdown
        json_output: Output in JSON format
    
    Returns:
        int: Exit code (0 = safe, 1 = malicious)
    """
    result = detector.detect(prompt)
    
    if json_output:
        # JSON output for scripting
        output = {
            'prompt': prompt,
            'is_injection': result.is_injection,
            'confidence': result.confidence,
            'explanation': result.explanation,
            'scores': {
                'rule': result.rule_score,
                'statistical': result.statistical_score,
                'semantic': result.semantic_score
            },
            'detection_methods': result.detection_methods
        }
        print(json.dumps(output, indent=2))
    else:
        # Human-readable output
        if result.is_injection:
            print("❌ MALICIOUS - Prompt injection detected!")
            print(f"   Confidence: {result.confidence:.1%}")
            print(f"   Reason: {result.explanation}")
            
            if verbose:
                print(f"\n   Score Breakdown:")
                print(f"   - Rule-based: {result.rule_score:.2f}")
                print(f"   - Statistical: {result.statistical_score:.2f}")
                print(f"   - Semantic: {result.semantic_score:.2f}")
                print(f"   - Final: {result.final_score:.2f}")
                print(f"   - Threshold: {detector.threshold:.2f}")
                print(f"   - Methods detected: {', '.join(result.detection_methods)}")
        else:
            print("✅ SAFE - No injection detected")
            print(f"   Confidence: {(1-result.confidence):.1%}")
            
            if verbose:
                print(f"\n   Score Breakdown:")
                print(f"   - Rule-based: {result.rule_score:.2f}")
                print(f"   - Statistical: {result.statistical_score:.2f}")
                print(f"   - Semantic: {result.semantic_score:.2f}")
                print(f"   - Final: {result.final_score:.2f}")
    
    return 1 if result.is_injection else 0


def check_file(detector, filepath, verbose=False, json_output=False):
    """
    Check multiple prompts from file.
    
    File format: One prompt per line
    
    Args:
        detector: EnsembleDetector instance
        filepath: Path to file with prompts
        verbose: Show detailed results
        json_output: Output in JSON format
    
    Returns:
        int: Number of malicious prompts detected
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            prompts = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: File not found: {filepath}", file=sys.stderr)
        return -1
    except Exception as e:
        print(f"❌ Error reading file: {e}", file=sys.stderr)
        return -1
    
    if not prompts:
        print("❌ Error: File is empty", file=sys.stderr)
        return -1
    
    results = []
    malicious_count = 0
    
    for i, prompt in enumerate(prompts, 1):
        result = detector.detect(prompt)
        
        if result.is_injection:
            malicious_count += 1
        
        results.append({
            'line': i,
            'prompt': prompt,
            'is_injection': result.is_injection,
            'confidence': result.confidence,
            'explanation': result.explanation
        })
    
    if json_output:
        # JSON output
        output = {
            'total': len(prompts),
            'malicious': malicious_count,
            'safe': len(prompts) - malicious_count,
            'results': results
        }
        print(json.dumps(output, indent=2))
    else:
        # Human-readable summary
        print(f"\n📊 Summary:")
        print(f"   Total prompts: {len(prompts)}")
        print(f"   Malicious: {malicious_count}")
        print(f"   Safe: {len(prompts) - malicious_count}")
        print(f"   Accuracy: {((len(prompts) - malicious_count) / len(prompts) * 100):.1f}%")
        
        if malicious_count > 0:
            print(f"\n❌ Malicious prompts detected:")
            for r in results:
                if r['is_injection']:
                    print(f"   Line {r['line']}: {r['prompt'][:60]}...")
                    if verbose:
                        print(f"      Confidence: {r['confidence']:.1%}")
                        print(f"      Reason: {r['explanation']}")
    
    return malicious_count


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description='Prompt-Shield CLI - Check prompts for injection attempts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "What is 2+2?"
  %(prog)s "Ignore all instructions" --verbose
  %(prog)s --file prompts.txt
  %(prog)s --file prompts.txt --threshold 0.6 --json
        """
    )
    
    parser.add_argument(
        'prompt',
        nargs='?',
        help='Prompt to check (or use --file for batch)'
    )
    
    parser.add_argument(
        '--file', '-f',
        help='Check prompts from file (one per line)'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=0.7,
        help='Detection threshold (0.5-0.9, default: 0.7)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed scoring breakdown'
    )
    
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output in JSON format for scripting'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.prompt and not args.file:
        parser.print_help()
        sys.exit(1)
    
    if args.prompt and args.file:
        print("❌ Error: Specify either prompt or --file, not both", file=sys.stderr)
        sys.exit(1)
    
    # Validate threshold
    if not 0.0 <= args.threshold <= 1.0:
        print("❌ Error: Threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)
    
    # Initialize detector
    if not args.json and args.verbose:
        print(f"🛡️  Prompt-Shield CLI (threshold={args.threshold})")
        print()
    
    detector = EnsembleDetector(threshold=args.threshold)
    
    # Check prompt(s)
    if args.file:
        exit_code = check_file(detector, args.file, args.verbose, args.json)
        sys.exit(min(exit_code, 1))  # Return 0 (safe) or 1 (malicious found)
    else:
        exit_code = check_prompt(detector, args.prompt, args.verbose, args.json)
        sys.exit(exit_code)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
