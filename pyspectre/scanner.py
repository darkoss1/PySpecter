#!/usr/bin/env python3
"""
PySpectre Scanner
=================
File and directory scanning functionality for PySpectre.
Usage as module:
    from pyspectre import scan_file, scan_directory
    results = scan_file("path/to/file.py")
    results = scan_directory("path/to/folder")
Usage as CLI:
    python -m pyspectre.scanner [--dir FOLDER] [--log LOG_FILE]
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pyspectre.execution.executor import ExecutionConfig, SymbolicExecutor


@dataclass
class ScanResult:
    """Result of scanning a single file."""

    file_path: str
    timestamp: str
    issues: list[dict[str, Any]] = field(default_factory=list)
    code_objects: int = 0
    paths_explored: int = 0
    error: str = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "timestamp": self.timestamp,
            "issues": self.issues,
            "code_objects": self.code_objects,
            "paths_explored": self.paths_explored,
            "error": self.error,
        }

    def __repr__(self) -> str:
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"


class ScanSession:
    """Tracks all scans in a session."""

    def __init__(self, log_file: Path = None):
        self.results: list[ScanResult] = []
        self.start_time = datetime.now()
        self.log_file = log_file or Path(
            f"scan_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )

    def add_result(self, result: ScanResult):
        self.results.append(result)
        self._save_log()

    def _save_log(self):
        """Save results to log file."""
        log_data = {
            "session_start": self.start_time.isoformat(),
            "last_update": datetime.now().isoformat(),
            "total_files": len(self.results),
            "total_issues": sum(len(r.issues) for r in self.results),
            "scans": [r.to_dict() for r in self.results],
        }
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2)

    def get_summary(self) -> dict[str, Any]:
        """Get session summary statistics."""
        total_issues = sum(len(r.issues) for r in self.results)
        issue_counts = {}
        for r in self.results:
            for issue in r.issues:
                kind = issue.get("kind", "UNKNOWN")
                issue_counts[kind] = issue_counts.get(kind, 0) + 1
        return {
            "files_scanned": len(self.results),
            "total_issues": total_issues,
            "issue_breakdown": issue_counts,
            "files_with_issues": sum(1 for r in self.results if r.issues),
            "files_clean": sum(1 for r in self.results if not r.issues and not r.error),
            "files_error": sum(1 for r in self.results if r.error),
        }


session: ScanSession = None


def get_all_code_objects(code):
    """Recursively extract all code objects (functions, classes, lambdas)."""
    code_objects = [code]
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            code_objects.extend(get_all_code_objects(const))
    return code_objects


def analyze_file(file_path: Path) -> ScanResult:
    """Run PySpectre analysis on a single file."""
    global session
    print(f"\n{'='*70}")
    print(f"🔍 Scanning: {file_path}")
    print("=" * 70)
    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
        code_obj = compile(content, str(file_path), "exec")
        all_code = get_all_code_objects(code_obj)
        result.code_objects = len(all_code)
        config = ExecutionConfig(
            max_paths=100, max_depth=50, max_iterations=5000, timeout_seconds=30.0
        )
        executor = SymbolicExecutor(config=config)
        all_issues = []
        total_paths = 0
        for code in all_code:
            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
            try:
                exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)
                all_issues.extend(exec_result.issues)
                total_paths += exec_result.paths_explored
            except Exception:
                pass
        result.paths_explored = total_paths
        seen = set()
        for issue in all_issues:
            msg = f"[{issue.kind.name}] {issue.message} (Line {issue.line_number})"
            if msg not in seen:
                seen.add(msg)
                result.issues.append(
                    {
                        "kind": issue.kind.name,
                        "message": issue.message,
                        "line": issue.line_number,
                        "pc": issue.pc,
                        "counterexample": issue.get_counterexample(),
                    }
                )
        if result.issues:
            print(f"\n⚠️  Found {len(result.issues)} potential issues:\n")
            for issue in result.issues:
                print(f"   • [{issue['kind']}] {issue['message']} (Line {issue['line']})")
                if issue["counterexample"]:
                    for var, val in issue["counterexample"].items():
                        print(f"       └─ {var} = {val}")
        else:
            print("\n✅ No issues found!")
        print(
            f"\n   📊 Stats: {result.code_objects} code objects | {result.paths_explored} paths explored"
        )
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
        print(f"\n❌ {result.error}")
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        print(f"\n❌ {result.error}")
    if session:
        session.add_result(result)
    return result


def scan_file(
    file_path: str | Path, verbose: bool = False, max_paths: int = 100, timeout: float = 30.0
) -> ScanResult:
    """
    Scan a single Python file for potential bugs.
    Args:
        file_path: Path to the Python file
        verbose: Print detailed output
        max_paths: Maximum paths to explore per function
        timeout: Timeout in seconds
    Returns:
        ScanResult with issues found
    Example:
        >>> result = scan_file("mycode.py")
        >>> for issue in result.issues:
        ...     print(f"{issue['kind']}: {issue['message']}")
    """
    file_path = Path(file_path)
    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
        code_obj = compile(content, str(file_path), "exec")
        all_code = get_all_code_objects(code_obj)
        result.code_objects = len(all_code)
        config = ExecutionConfig(
            max_paths=max_paths, max_depth=50, max_iterations=5000, timeout_seconds=timeout
        )
        executor = SymbolicExecutor(config=config)
        all_issues = []
        total_paths = 0
        for code in all_code:
            symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
            try:
                exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)
                all_issues.extend(exec_result.issues)
                total_paths += exec_result.paths_explored
            except Exception:
                pass
        result.paths_explored = total_paths
        seen = set()
        for issue in all_issues:
            msg = f"[{issue.kind.name}] {issue.message} (Line {issue.line_number})"
            if msg not in seen:
                seen.add(msg)
                result.issues.append(
                    {
                        "kind": issue.kind.name,
                        "message": issue.message,
                        "line": issue.line_number,
                        "pc": issue.pc,
                        "counterexample": issue.get_counterexample(),
                    }
                )
        if verbose:
            if result.issues:
                print(f"⚠️  {file_path}: {len(result.issues)} issues found")
            else:
                print(f"✅ {file_path}: No issues")
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
    except Exception as e:
        result.error = f"Analysis Error: {e}"
    return result


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 100,
    timeout: float = 30.0,
) -> list[ScanResult]:
    """
    Scan all Python files in a directory for potential bugs.
    Args:
        dir_path: Path to directory
        pattern: Glob pattern for files (default: **/*.py for recursive)
        verbose: Print progress
        max_paths: Maximum paths per function
        timeout: Timeout per file
    Returns:
        List of ScanResult for each file
    Example:
        >>> results = scan_directory("src/")
        >>> total_issues = sum(len(r.issues) for r in results)
        >>> print(f"Found {total_issues} total issues")
    """
    dir_path = Path(dir_path)
    results = []
    files = list(dir_path.glob(pattern))
    if verbose:
        print(f"Scanning {len(files)} files in {dir_path}...")
    for i, file_path in enumerate(sorted(files), 1):
        if verbose:
            print(f"[{i}/{len(files)}] {file_path.name}...", end=" ", flush=True)
        result = scan_file(file_path, verbose=False, max_paths=max_paths, timeout=timeout)
        results.append(result)
        if verbose:
            if result.error:
                print("❌ Error")
            elif result.issues:
                print(f"⚠️  {len(result.issues)} issues")
            else:
                print("✅")
    if verbose:
        total_issues = sum(len(r.issues) for r in results)
        files_with_issues = sum(1 for r in results if r.issues)
        print(f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files")
    return results


def on_file_event(event):
    """Handle file system events."""
    from pyspectre.core.watch import FileEventType

    if event.event_type in (FileEventType.CREATED, FileEventType.MODIFIED):
        if event.path.suffix == ".py":
            analyze_file(event.path)


def print_final_summary():
    """Print final session summary."""
    global session
    if not session:
        return
    summary = session.get_summary()
    print(f"\n\n{'='*70}")
    print("📋 SESSION SUMMARY")
    print("=" * 70)
    print(f"""
   Files scanned:     {summary['files_scanned']}
   Files with issues: {summary['files_with_issues']}
   Files clean:       {summary['files_clean']}
   Files with errors: {summary['files_error']}
   Total issues:      {summary['total_issues']}
""")
    if summary["issue_breakdown"]:
        print("   Issue breakdown:")
        for kind, count in sorted(summary["issue_breakdown"].items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 30)
            print(f"      {kind:<25} {count:>4} {bar}")
    print(f"\n   📁 Log saved to: {session.log_file}")
    print("=" * 70)


def main():
    """CLI entry point for watch mode."""
    global session
    from pyspectre.core.watch import FileWatcher

    parser = argparse.ArgumentParser(description="PySpectre Scanner")
    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        default=".",
        help="Directory to scan/watch (default: current directory)",
    )
    parser.add_argument(
        "--log",
        "-l",
        type=str,
        default=None,
        help="Log file path (default: scan_log_TIMESTAMP.json)",
    )
    parser.add_argument(
        "--watch",
        "-w",
        action="store_true",
        help="Watch mode: continuously monitor for file changes",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Scan subdirectories recursively (default: True)",
    )
    args = parser.parse_args()
    scan_dir = Path(args.dir)
    log_file = Path(args.log) if args.log else None
    if not scan_dir.exists():
        print(f"Error: Directory '{scan_dir}' does not exist")
        sys.exit(1)
    session = ScanSession(log_file=log_file)
    pattern = "**/*.py" if args.recursive else "*.py"
    existing_files = list(scan_dir.glob(pattern))
    if existing_files:
        print(f"Scanning {len(existing_files)} Python files in {scan_dir}...\n")
        for f in sorted(existing_files):
            analyze_file(f)
    else:
        print(f"No Python files found in {scan_dir}")
    if args.watch:
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                   PySpectre Scanner - Watch Mode                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  Watching: {str(scan_dir):<56} ║
║  Log:      {str(session.log_file):<56} ║
║  Press Ctrl+C to stop and see summary.                               ║
╚══════════════════════════════════════════════════════════════════════╝
""")
        watcher = FileWatcher(paths=[scan_dir], patterns=["*.py"])
        watcher.on_change(on_file_event)
        watcher.start()
        try:
            print("👁️  Watching for file changes...")
            while True:
                import time

                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nStopping watcher...")
            watcher.stop()
    print_final_summary()
    print("\nDone.")


if __name__ == "__main__":
    main()
