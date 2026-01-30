"""Command-line interface for PySpectre.
Provides two modes:
1. Single function analysis: pyspectre file.py -f function_name
2. Full file/directory scan: pyspectre scan path/to/code
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from pyspectre.api import analyze_file
from pyspectre.reporting.formatters import format_result
def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="pyspectre",
        description="🔮 PySpectre - Symbolic Execution Engine for Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan entire file (auto-discover all functions)
  pyspectre scan myfile.py
  # Scan entire directory
  pyspectre scan ./src --recursive
  # Analyze specific function  
  pyspectre analyze myfile.py -f my_function
  # Generate JSON report for AI
  pyspectre scan myfile.py --format json
  # Quick check with limited exploration
  pyspectre scan myfile.py --max-paths 50
For more info: https://github.com/pyspectre
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="PySpectre 1.0.0",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan file(s) for bugs (auto-discovers all functions)",
        description="Automatically scan all functions in a file or directory",
    )
    scan_parser.add_argument(
        "path",
        type=str,
        help="Python file or directory to scan",
    )
    scan_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan directories",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--max-paths",
        type=int,
        default=1000,
        help="Max paths per function (default: 1000)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Timeout per function in seconds (default: 60)",
    )
    scan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker processes (default: CPU count)",
    )
    scan_parser.add_argument(
        "--auto",
        action="store_true",
        help="Automatically tune configuration based on code complexity",
    )
    scan_parser.add_argument(
        "--reproduce",
        action="store_true",
        help="Generate reproduction scripts for detected issues",
    )
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a specific function",
        description="Run symbolic execution on a specific function",
    )
    analyze_parser.add_argument(
        "file",
        type=str,
        help="Python source file",
    )
    analyze_parser.add_argument(
        "-f",
        "--function",
        type=str,
        required=True,
        help="Function name to analyze",
    )
    analyze_parser.add_argument(
        "--args",
        nargs="*",
        help="Symbolic arguments: name:type (e.g., x:int y:str)",
    )
    analyze_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "html", "markdown", "sarif"],
        default="text",
        help="Output format",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path",
    )
    analyze_parser.add_argument(
        "--max-paths",
        type=int,
        default=1000,
        help="Maximum paths to explore",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Timeout in seconds",
    )
    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "legacy_file",
        type=str,
        nargs="?",
        help="(Legacy) Python file to analyze",
    )
    parser.add_argument(
        "-f",
        "--function",
        type=str,
        dest="legacy_function",
        help="(Legacy) Function to analyze",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "html", "markdown", "sarif"],
        default="text",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
    )
    return parser
def cmd_scan(args) -> int:
    """Execute scan command."""
    import json
    from pyspectre.scanner import scan_directory, scan_file
    path = Path(args.path)
    if not path.exists():
        print(f"❌ Error: Path not found: {path}", file=sys.stderr)
        return 1
    if args.verbose:
        print(f"🔍 Scanning: {path}")
    if path.is_file():
        results = [
            scan_file(path, verbose=args.verbose, max_paths=args.max_paths, timeout=args.timeout)
        ]
    else:
        pattern = "**/*.py" if args.recursive else "*.py"
        results = scan_directory(
            args.path,
            pattern=pattern,
            verbose=args.verbose,
            max_paths=args.max_paths,
            timeout=args.timeout,
            workers=args.workers,
            auto_tune=args.auto,
        )
    total_issues = sum(len(r.issues) for r in results)
    if args.format == "json":
        output_data = {
            "pyspectre_version": "1.0.0",
            "files_scanned": len(results),
            "total_issues": total_issues,
            "results": [r.to_dict() for r in results],
        }
        output = json.dumps(output_data, indent=2, default=str)
    elif args.format == "sarif":
        from pyspectre.reporting.sarif import SARIFGenerator
        generator = SARIFGenerator()
        for r in results:
            for issue in r.issues:
                generator.add_issue_from_dict(issue, r.file_path)
        output = generator.to_json()
    else:
        lines = []
        lines.append("")
        lines.append("╔" + "═" * 58 + "╗")
        lines.append("║" + "  🔮 PySpectre Scan Results".center(58) + "║")
        lines.append("╚" + "═" * 58 + "╝")
        lines.append("")
        lines.append(f"  📁 Scanned: {len(results)} file(s)")
        lines.append(f"  🐛 Issues:  {total_issues}")
        lines.append("")
        if total_issues == 0:
            lines.append("  ✅ No issues found!")
        else:
            for result in results:
                if result.issues:
                    lines.append(f"  ─── {result.file_path} ───")
                    for issue in result.issues:
                        kind = issue.get("kind", "UNKNOWN")
                        msg = issue.get("message", "")
                        line = issue.get("line_number", "?")
                        if kind in ("DIVISION_BY_ZERO", "ASSERTION_ERROR"):
                            icon = "🔴"
                        elif kind in ("INDEX_ERROR", "KEY_ERROR"):
                            icon = "🟠"
                        else:
                            icon = "🟡"
                        lines.append(f"    {icon} [{kind}] Line {line}: {msg}")
                        ce = issue.get("counterexample")
                        if ce:
                            ce_str = ", ".join(f"{k}={v}" for k, v in ce.items())
                            lines.append(f"       ↳ Trigger: {ce_str}")
                    if args.reproduce and result.issues:
                        from pyspectre.reporting.reproduction import ReproductionGenerator
                        generator = ReproductionGenerator()
                        lines.append("")
                        lines.append("    [!] Reproduction Scripts:")
                        for issue in result.issues:
                            func = issue.get("function_name", "unknown")
                            class_name = issue.get("class_name")
                            src = str(result.file_path)
                            class IssueWrapper:
                                def __init__(self, data):
                                    self.counterexample = data.get("counterexample")
                                    self.kind = type("Kind", (), {"name": data.get("kind")})
                                    self.message = data.get("message")
                                    self.class_name = data.get("class_name")
                            issue_obj = IssueWrapper(issue)
                            if issue_obj.counterexample:
                                script_path = generator.generate(
                                    issue_obj, func, src, class_name=class_name
                                )
                                if script_path:
                                    lines.append(f"       + {script_path}")
                    lines.append("")
        lines.append("─" * 60)
        output = "\n".join(lines)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"📄 Report saved to: {args.output}")
    else:
        print(output)
    return 1 if total_issues > 0 else 0
def cmd_analyze(args) -> int:
    """Execute analyze command for single function."""
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Error: File not found: {filepath}", file=sys.stderr)
        return 1
    symbolic_args = {}
    if args.args:
        for arg in args.args:
            if ":" in arg:
                name, type_hint = arg.split(":", 1)
                symbolic_args[name.strip()] = type_hint.strip()
    if args.verbose:
        print(f"🔍 Analyzing {args.function}() in {filepath}")
    try:
        result = analyze_file(
            filepath=filepath,
            function_name=args.function,
            symbolic_args=symbolic_args,
            max_paths=args.max_paths,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        output = format_result(result, args.format)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            if args.verbose:
                print(f"📄 Report saved to: {args.output}")
        else:
            print(output)
        return 1 if result.has_issues() else 0
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1
def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "analyze":
        return cmd_analyze(args)
    if args.legacy_file and args.legacy_function:
        args.command = "analyze"
        args.file = args.legacy_file
        args.function = args.legacy_function
        args.args = None
        return cmd_analyze(args)
    parser.print_help()
    return 0
if __name__ == "__main__":
    sys.exit(main())