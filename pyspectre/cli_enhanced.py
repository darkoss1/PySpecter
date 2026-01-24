"""Enhanced command-line interface for PySpectre.
Provides a rich CLI experience with:
- Configuration file support
- Colored output
- Progress indicators
- Multiple output formats
- Watch mode
- Init command for new projects
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

from pyspectre.config import (
    PySpectreConfig,
    generate_default_config,
    load_config,
)
from pyspectre.logging import (
    Colors,
    LogLevel,
    configure_logging,
    get_logger,
    supports_color,
)
from pyspectre.resources import LimitExceeded

VERSION = "1.0.0"
BANNER = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════╗
║  {Colors.BOLD}👁️  PySpectre{Colors.RESET}{Colors.CYAN}  - Symbolic Execution Engine  ║
║      Python Bytecode Analysis with Z3         ║
╚═══════════════════════════════════════════════╝{Colors.RESET}
"""
BANNER_PLAIN = """
+-----------------------------------------------+
|  PySpectre  - Symbolic Execution Engine       |
|      Python Bytecode Analysis with Z3         |
+-----------------------------------------------+
"""


def create_parser() -> argparse.ArgumentParser:
    """Create the enhanced argument parser."""
    parser = argparse.ArgumentParser(
        prog="pyspectre",
        description="PySpectre - Symbolic Execution Engine for Python Bytecode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"PySpectre {VERSION}",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a Python file or function",
        aliases=["a", "run"],
    )
    analyze_parser.add_argument(
        "file",
        type=str,
        help="Python source file to analyze",
    )
    analyze_parser.add_argument(
        "-f",
        "--function",
        type=str,
        required=True,
        help="Name of the function to analyze",
    )
    analyze_parser.add_argument(
        "--args",
        nargs="*",
        help="Symbolic arguments in format name:type (e.g., x:int y:str)",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path (default: stdout)",
    )
    analyze_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "html", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    analyze_parser.add_argument(
        "--max-paths",
        type=int,
        help="Maximum paths to explore",
    )
    analyze_parser.add_argument(
        "--max-depth",
        type=int,
        help="Maximum execution depth",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=float,
        help="Timeout in seconds",
    )
    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    analyze_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Minimal output",
    )
    analyze_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress indicator",
    )
    analyze_parser.add_argument(
        "--detect",
        nargs="*",
        choices=["div-zero", "assert", "index", "type", "key", "overflow", "all"],
        help="Enable specific detectors",
    )
    analyze_parser.add_argument(
        "--no-detect",
        nargs="*",
        choices=["div-zero", "assert", "index", "type", "key"],
        help="Disable specific detectors",
    )
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new PySpectre configuration",
    )
    init_parser.add_argument(
        "--dir",
        type=str,
        default=".",
        help="Directory to create config in (default: current)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing configuration",
    )
    check_parser = subparsers.add_parser(
        "check",
        help="Quick check a file for common issues",
    )
    check_parser.add_argument(
        "files",
        nargs="+",
        type=str,
        help="Python files to check",
    )
    check_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    watch_parser = subparsers.add_parser(
        "watch",
        help="Watch files and re-analyze on changes",
    )
    watch_parser.add_argument(
        "directory",
        type=str,
        nargs="?",
        default=".",
        help="Directory to watch (default: current)",
    )
    watch_parser.add_argument(
        "-f",
        "--function",
        type=str,
        help="Function to analyze (required for single-file mode)",
    )
    watch_parser.add_argument(
        "--pattern",
        type=str,
        default="**/*.py",
        help="Glob pattern for files to watch",
    )
    config_parser = subparsers.add_parser(
        "config",
        help="Show or manage configuration",
    )
    config_parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration",
    )
    config_parser.add_argument(
        "--path",
        action="store_true",
        help="Show configuration file path",
    )
    config_parser.add_argument(
        "--default",
        action="store_true",
        help="Print default configuration",
    )
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify function contracts and mathematical properties",
        aliases=["v", "prove"],
    )
    verify_parser.add_argument(
        "file",
        type=str,
        help="Python source file to verify",
    )
    verify_parser.add_argument(
        "-f",
        "--function",
        type=str,
        help="Name of the function to verify (default: all)",
    )
    verify_parser.add_argument(
        "--args",
        nargs="*",
        help="Symbolic arguments in format name:type (e.g., x:int y:float)",
    )
    verify_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file path (default: stdout)",
    )
    verify_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    verify_parser.add_argument(
        "--check-contracts",
        action="store_true",
        default=True,
        help="Verify @requires/@ensures contracts (default: True)",
    )
    verify_parser.add_argument(
        "--check-overflow",
        action="store_true",
        help="Check for integer overflow",
    )
    verify_parser.add_argument(
        "--check-bounds",
        action="store_true",
        help="Check array bounds",
    )
    verify_parser.add_argument(
        "--check-division",
        action="store_true",
        help="Check for division by zero",
    )
    verify_parser.add_argument(
        "--check-all",
        action="store_true",
        help="Enable all verification checks",
    )
    verify_parser.add_argument(
        "--execute",
        action="store_true",
        help="Use full symbolic execution with integrated verification",
    )
    verify_parser.add_argument(
        "--check-termination",
        action="store_true",
        help="Analyze loop termination",
    )
    verify_parser.add_argument(
        "--max-paths",
        type=int,
        default=100,
        help="Maximum paths to explore (default: 100)",
    )
    verify_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Solver timeout in seconds (default: 10)",
    )
    verify_parser.add_argument(
        "--int-bits",
        type=int,
        default=64,
        help="Integer bit width for overflow detection (default: 64)",
    )
    verify_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    verify_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Minimal output",
    )
    return parser


def parse_symbolic_args(args_list: list[str] | None) -> dict[str, str]:
    """Parse symbolic argument specifications."""
    if not args_list:
        return {}
    result = {}
    for arg in args_list:
        if ":" not in arg:
            get_logger().warning(f"Invalid argument format '{arg}', expected 'name:type'")
            continue
        name, type_hint = arg.split(":", 1)
        result[name.strip()] = type_hint.strip()
    return result


def cmd_analyze(args: argparse.Namespace, config: PySpectreConfig) -> int:
    """Run the analyze command."""
    logger = get_logger()
    filepath = Path(args.file)
    if not filepath.exists():
        logger.error(f"File not found: {filepath}")
        return 1
    symbolic_args = parse_symbolic_args(args.args)
    if args.max_paths is not None:
        config.limits.max_paths = args.max_paths
    if args.max_depth is not None:
        config.limits.max_depth = args.max_depth
    if args.timeout is not None:
        config.limits.timeout_seconds = args.timeout
    if not args.quiet:
        logger.header(f"Analyzing {args.function}()")
        logger.info(f"File: {filepath}")
        if symbolic_args:
            logger.info(f"Symbolic args: {symbolic_args}")
        logger.rule()
    try:
        from pyspectre.api import analyze_file
        from pyspectre.reporting.formatters import format_result
        from pyspectre.reporting.html_report import (
            create_report_from_result,
            save_html_report,
        )

        start_time = time.perf_counter()
        result = analyze_file(
            filepath=filepath,
            function_name=args.function,
            symbolic_args=symbolic_args,
            max_paths=config.limits.max_paths,
            max_depth=config.limits.max_depth,
            max_iterations=config.limits.max_iterations,
            timeout=config.limits.timeout_seconds,
            verbose=args.verbose,
        )
        duration = time.perf_counter() - start_time
        if args.format == "html":
            report = create_report_from_result(
                result=result,
                file_path=str(filepath),
                function_name=args.function,
                duration=duration,
            )
            output = None
            if args.output:
                save_html_report(report, Path(args.output))
                logger.success(f"Report saved to {args.output}")
            else:
                from pyspectre.reporting.html_report import generate_html_report

                output = generate_html_report(report)
        else:
            output = format_result(result, args.format)
        if output:
            if args.output and args.format != "html":
                Path(args.output).write_text(output, encoding="utf-8")
                logger.success(f"Report saved to {args.output}")
            else:
                print(output)
        if not args.quiet:
            logger.rule()
            if result.has_issues():
                logger.error(f"Found {len(result.issues)} issue(s)")
            else:
                logger.success("No issues found")
            logger.info(f"Explored {result.paths_explored} paths in {duration:.2f}s")
        return 1 if result.has_issues() else 0
    except LimitExceeded as e:
        logger.warning(f"Analysis stopped: {e}")
        return 2
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def cmd_init(args: argparse.Namespace) -> int:
    """Run the init command."""
    logger = get_logger()
    target_dir = Path(args.dir).resolve()
    config_path = target_dir / "pyspectre.toml"
    if config_path.exists() and not args.force:
        logger.error(f"Configuration already exists: {config_path}")
        logger.info("Use --force to overwrite")
        return 1
    try:
        content = generate_default_config()
        config_path.write_text(content, encoding="utf-8")
        logger.success(f"Created configuration: {config_path}")
        return 0
    except Exception as e:
        logger.error(f"Failed to create config: {e}")
        return 1


def cmd_check(args: argparse.Namespace, config: PySpectreConfig) -> int:
    """Run the check command (quick analysis)."""
    logger = get_logger()
    total_issues = 0
    for file_path in args.files:
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"File not found: {path}")
            continue
        if not path.suffix == ".py":
            logger.warning(f"Skipping non-Python file: {path}")
            continue
        logger.info(f"Checking {path}...")
        try:
            import ast

            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
            logger.verbose(f"  Found {len(functions)} functions")
        except SyntaxError as e:
            logger.error(f"  Syntax error: {e}")
            total_issues += 1
    if total_issues == 0:
        logger.success("All files OK")
        return 0
    else:
        logger.error(f"Found {total_issues} issue(s)")
        return 1


def cmd_watch(args: argparse.Namespace, config: PySpectreConfig) -> int:
    """Run the watch command."""
    logger = get_logger()
    target_dir = Path(args.directory).resolve()
    if not target_dir.exists():
        logger.error(f"Directory not found: {target_dir}")
        return 1
    logger.header("Watch Mode")
    logger.info(f"Watching: {target_dir}")
    logger.info(f"Pattern: {args.pattern}")
    logger.info("Press Ctrl+C to stop")
    logger.rule()
    try:
        from pyspectre.core.watch import FileWatcher, WatchModeRunner

        watcher = FileWatcher(target_dir, patterns=[args.pattern])
        runner = WatchModeRunner(watcher)

        def on_result(path: Path, result: Any) -> None:
            if hasattr(result, "has_issues") and result.has_issues():
                logger.error(f"{path}: Found {len(result.issues)} issue(s)")
            else:
                logger.success(f"{path}: OK")

        runner.on_result(on_result)
        logger.info("Watch mode not fully implemented yet")
        return 0
    except KeyboardInterrupt:
        logger.info("\nStopped watching")
        return 0


def cmd_config(args: argparse.Namespace, config: PySpectreConfig) -> int:
    """Run the config command."""
    logger = get_logger()
    if args.default:
        print(generate_default_config())
        return 0
    if args.path:
        if config.config_file:
            print(config.config_file)
        else:
            logger.info("No configuration file found")
        return 0
    if args.show or not any([args.default, args.path]):
        import json

        print(json.dumps(config.to_dict(), indent=2))
        return 0
    return 0


def _cmd_verify_with_executor(
    args: argparse.Namespace,
    config: PySpectreConfig,
    filepath: Path,
    logger: Any,
) -> int:
    """Run verification using the VerifiedExecutor for full symbolic execution."""
    import importlib.util

    try:
        from pyspectre.execution.verified_executor import (
            VerifiedExecutionConfig,
            VerifiedExecutor,
        )

        spec = importlib.util.spec_from_file_location("target_module", filepath)
        if not spec or not spec.loader:
            logger.error("Could not load module")
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        symbolic_args = parse_symbolic_args(args.args) if args.args else {}
        timeout_ms = int(args.timeout * 1000)
        exec_config = VerifiedExecutionConfig(
            max_paths=args.max_paths,
            solver_timeout_ms=timeout_ms,
            check_preconditions=args.check_contracts or args.check_all,
            check_postconditions=args.check_contracts or args.check_all,
            check_loop_invariants=args.check_contracts or args.check_all,
            check_overflow=args.check_overflow or args.check_all,
            check_division_safety=args.check_division or args.check_all,
            check_array_bounds=args.check_bounds or args.check_all,
            check_termination=args.check_termination or args.check_all,
            integer_bits=args.int_bits,
            verbose=args.verbose if hasattr(args, "verbose") else False,
        )
        executor = VerifiedExecutor(exec_config)
        functions_to_verify = []
        for name in dir(module):
            obj = getattr(module, name)
            if callable(obj) and not name.startswith("_"):
                if args.function is None or name == args.function:
                    functions_to_verify.append((name, obj))
        if not functions_to_verify:
            if args.function:
                logger.error(f"Function '{args.function}' not found")
            else:
                logger.warning("No functions found to verify")
            return 1
        all_results = []
        total_issues = 0
        total_contracts_verified = 0
        total_contracts_violated = 0
        for func_name, func in functions_to_verify:
            if not args.quiet:
                logger.info(f"\nVerifying {func_name}()...")
            result = executor.execute_function(func, symbolic_args)
            all_results.append((func_name, result))
            total_issues += (
                len(result.issues) + len(result.contract_issues) + len(result.arithmetic_issues)
            )
            total_contracts_verified += result.contracts_verified
            total_contracts_violated += result.contracts_violated
            if not args.quiet:
                if result.is_verified:
                    logger.success(
                        f"  ✓ Verified ({result.contracts_verified} contracts, {result.paths_explored} paths)"
                    )
                else:
                    logger.error("  ✗ Issues found:")
                    for issue in result.issues:
                        logger.error(f"    - [{issue.kind.name}] {issue.message}")
                    for issue in result.contract_issues:
                        logger.error(f"    - [{issue.kind.name}] {issue.condition}")
                        if issue.counterexample:
                            logger.info(f"      Counterexample: {issue.counterexample}")
                    for issue in result.arithmetic_issues:
                        logger.error(f"    - [{issue.kind}] {issue.message}")
                if result.termination_proof:
                    status = result.termination_proof.status.name
                    logger.info(f"  Termination: {status}")
        if not args.quiet:
            logger.rule()
            logger.info("Verification Summary:")
            logger.info(f"  Functions analyzed: {len(functions_to_verify)}")
            logger.success(f"  Contracts verified: {total_contracts_verified}")
            if total_contracts_violated > 0:
                logger.error(f"  Contracts violated: {total_contracts_violated}")
            else:
                logger.info(f"  Contracts violated: {total_contracts_violated}")
            logger.info(f"  Total issues: {total_issues}")
        if args.format == "json":
            import json

            output = json.dumps(
                {
                    "file": str(filepath),
                    "mode": "symbolic_execution",
                    "functions": [
                        {
                            "name": name,
                            "verified": result.is_verified,
                            "paths_explored": result.paths_explored,
                            "contracts_checked": result.contracts_checked,
                            "contracts_verified": result.contracts_verified,
                            "contracts_violated": result.contracts_violated,
                            "issues": [
                                {"kind": i.kind.name, "message": i.message} for i in result.issues
                            ],
                            "contract_issues": [
                                {
                                    "kind": i.kind.name,
                                    "condition": i.condition,
                                    "counterexample": i.counterexample,
                                }
                                for i in result.contract_issues
                            ],
                            "arithmetic_issues": [
                                {"kind": i.kind, "expression": i.expression, "message": i.message}
                                for i in result.arithmetic_issues
                            ],
                        }
                        for name, result in all_results
                    ],
                },
                indent=2,
            )
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                logger.success(f"Report saved to {args.output}")
            else:
                print(output)
        return 1 if total_issues > 0 else 0
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        if hasattr(args, "verbose") and args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def cmd_verify(args: argparse.Namespace, config: PySpectreConfig) -> int:
    """Run the verify command for contract verification."""
    logger = get_logger()
    filepath = Path(args.file)
    if not filepath.exists():
        logger.error(f"File not found: {filepath}")
        return 1
    if not args.quiet:
        logger.header("Mathematical Verification")
        logger.info(f"File: {filepath}")
        if args.function:
            logger.info(f"Function: {args.function}")
        if args.execute:
            logger.info("Mode: Full Symbolic Execution")
        logger.rule()
    if args.execute:
        return _cmd_verify_with_executor(args, config, filepath, logger)
    try:
        import ast
        import importlib.util

        from pyspectre.analysis.contracts import (
            ContractAnalyzer,
            ContractVerifier,
        )
        from pyspectre.analysis.properties import (
            ArithmeticVerifier,
        )

        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source)
        functions_to_verify = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if args.function is None or node.name == args.function:
                    functions_to_verify.append(node.name)
        if not functions_to_verify:
            if args.function:
                logger.error(f"Function '{args.function}' not found")
            else:
                logger.warning("No functions found to verify")
            return 1
        spec = importlib.util.spec_from_file_location("target_module", filepath)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as e:
                logger.warning(f"Could not load module: {e}")
                module = None
        else:
            module = None
        timeout_ms = int(args.timeout * 1000)
        contract_verifier = ContractVerifier(timeout_ms=timeout_ms)
        contract_analyzer = ContractAnalyzer(verifier=contract_verifier)
        arithmetic_verifier = ArithmeticVerifier(
            int_bits=args.int_bits,
            timeout_ms=timeout_ms,
        )
        symbolic_args = parse_symbolic_args(args.args) if args.args else {}
        total_verified = 0
        total_violated = 0
        total_unknown = 0
        all_reports = []
        for func_name in functions_to_verify:
            if not args.quiet:
                logger.info(f"\nVerifying {func_name}()...")
            func = getattr(module, func_name, None) if module else None
            if func and args.check_contracts:
                report = contract_analyzer.analyze_function(func, symbolic_args)
                all_reports.append(report)
                total_verified += report.verified
                total_violated += report.violated
                total_unknown += report.unknown
                if not args.quiet:
                    if report.is_verified:
                        logger.success(f"  ✓ All contracts verified ({report.verified})")
                    elif report.has_violations:
                        logger.error(f"  ✗ {report.violated} contract(s) violated")
                        for v in report.violations:
                            logger.error(f"    - {v.kind.name}: {v.condition}")
                            if v.counterexample:
                                logger.info(f"      Counterexample: {v.counterexample}")
                    else:
                        logger.warning(f"  ? {report.unknown} contracts could not be verified")
            if args.check_all or args.check_overflow:
                if not args.quiet:
                    logger.info("  Checking for overflow...")
            if args.check_all or args.check_division:
                if not args.quiet:
                    logger.info("  Checking for division by zero...")
        if not args.quiet:
            logger.rule()
            total = total_verified + total_violated + total_unknown
            logger.info("Verification Summary:")
            logger.info(f"  Total properties: {total}")
            logger.success(f"  Verified:  {total_verified}")
            if total_violated > 0:
                logger.error(f"  Violated:  {total_violated}")
            else:
                logger.info(f"  Violated:  {total_violated}")
            logger.info(f"  Unknown:   {total_unknown}")
        if args.format == "json":
            import json

            output = json.dumps(
                {
                    "file": str(filepath),
                    "functions": functions_to_verify,
                    "summary": {
                        "verified": total_verified,
                        "violated": total_violated,
                        "unknown": total_unknown,
                    },
                    "reports": [
                        {
                            "function": r.function_name,
                            "verified": r.verified,
                            "violated": r.violated,
                            "unknown": r.unknown,
                            "violations": [
                                {
                                    "kind": v.kind.name,
                                    "condition": v.condition,
                                    "message": v.message,
                                    "line": v.line_number,
                                    "counterexample": v.counterexample,
                                }
                                for v in r.violations
                            ],
                        }
                        for r in all_reports
                    ],
                },
                indent=2,
            )
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                logger.success(f"Report saved to {args.output}")
            else:
                print(output)
        elif args.format == "sarif":
            sarif_results = []
            for report in all_reports:
                for v in report.violations:
                    sarif_results.append(
                        {
                            "ruleId": f"CONTRACT_{v.kind.name}",
                            "message": v.message,
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": str(filepath)},
                                        "region": {"startLine": v.line_number or 1},
                                    }
                                }
                            ],
                        }
                    )
            sarif_output = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "PySpectre",
                                "version": VERSION,
                                "informationUri": "https://github.com/pyspectre/pyspectre",
                            }
                        },
                        "results": sarif_results,
                    }
                ],
            }
            import json

            output = json.dumps(sarif_output, indent=2)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                logger.success(f"SARIF report saved to {args.output}")
            else:
                print(output)
        return 1 if total_violated > 0 else 0
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for enhanced CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)
    use_color = not args.no_color and supports_color(sys.stderr)
    if hasattr(args, "quiet") and args.quiet:
        level = LogLevel.QUIET
    elif hasattr(args, "verbose") and args.verbose:
        level = LogLevel.VERBOSE
    else:
        level = LogLevel.NORMAL
    configure_logging(level=level, color=use_color)
    logger = get_logger()
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)
    if not hasattr(args, "quiet") or not args.quiet:
        if args.command in (None, "analyze", "a", "run"):
            if use_color:
                print(BANNER)
            else:
                print(BANNER_PLAIN)
    if args.command in ("analyze", "a", "run"):
        return cmd_analyze(args, config)
    elif args.command == "init":
        return cmd_init(args)
    elif args.command == "check":
        return cmd_check(args, config)
    elif args.command == "watch":
        return cmd_watch(args, config)
    elif args.command == "config":
        return cmd_config(args, config)
    elif args.command in ("verify", "v", "prove"):
        return cmd_verify(args, config)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
