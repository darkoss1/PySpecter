# PySpectre
 
 > [!IMPORTANT]
 > **EDUCATIONAL PURPOSES ONLY**
 > This project is a research prototype designed for studying symbolic execution and formal verification concepts. 
 > It is **NOT** intended for production use, security auditing, or critical systems verification. 
 > Use at your own risk.
 
 <div align="center">
 
 **Intelligent Formal Verification for Python using Z3 Theorem Prover**
 
 [![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
 [![Status: Educational](https://img.shields.io/badge/Status-Educational_Prototype-orange.svg)]()
 
 *Mathematically prove your Python code won't crash.*
 
 </div>

---

## 🚀 Features

- **Interprocedural Analysis**: Tracks bugs across function calls
- **Call Graph Building**: Understands how functions relate to each other
- **Function Summaries**: Caches analysis results for efficiency
- **Taint Tracking**: Follows untrusted data through your code
- **Mathematical Proofs**: Uses Z3 SMT solver for formal verification
- **12 Bug Types Detected**: Division by zero, null dereference, index out of bounds, and more
- **Full Symbolic Execution Engine**: Complete bytecode-level analysis
- **HTML/SARIF Reports**: Export results in multiple formats

## 📦 Installation

```bash
# Install Z3 solver (required)
pip install z3-solver

# Clone and install
git clone https://github.com/yourusername/pyspectre.git
cd pyspectre
pip install -e .
```

## 🔍 Quick Start

### Command Line

```bash
# Scan a file
python pyspectre_verify.py mycode.py

# Scan a directory
python pyspectre_verify.py src/

# Show call graph relationships
python pyspectre_verify.py . --call-graph

# Export JSON report
python pyspectre_verify.py src/ --json report.json

# Verbose output with timing
python pyspectre_verify.py . --verbose
```

### Python API

```python
from pyspectre.analysis.z3_prover import verify_function, Z3Engine

# Verify a single function
def risky_divide(x: int, y: int) -> int:
    return x // y

results = verify_function(risky_divide)
for r in results:
    if r.can_crash:
        print(f"Bug: {r.crash.description}")
        print(f"Counterexample: {r.counterexample}")

# Use the full engine for interprocedural analysis
engine = Z3Engine(
    timeout_ms=5000,
    interprocedural=True,
    track_taint=True
)
file_results = engine.verify_file("mycode.py")
```

## 🐛 Bug Types Detected

| Bug Type | Description | Example |
|----------|-------------|---------|
| ➗ Division by Zero | Division where denominator can be 0 | `x / y` where `y=0` |
| ➗ Modulo by Zero | Modulo where divisor can be 0 | `x % y` where `y=0` |
| ⬅️ Negative Shift | Bit shift with negative amount | `x << n` where `n<0` |
| 📦 Index Out of Bounds | Array access beyond bounds | `arr[i]` where `i >= len(arr)` |
| 🚫 None Dereference | Accessing attributes on None | `obj.method()` where `obj=None` |
| 🔀 Type Error | Type mismatch in operations | Operations on wrong types |
| 🔑 Key Error | Dictionary key not found | `d[key]` where key missing |
| 📛 Attribute Error | Missing attribute access | Missing method/property |
| ❌ Assertion Failure | Assertions that can fail | `assert x > 0` where `x<=0` |
| 🚧 Unreachable Code | Dead code paths | Code after `return` |
| ☠️ Tainted Data | Untrusted data to dangerous sink | SQL injection, etc. |
| 💥 Integer Overflow | Arithmetic overflow | Large number operations |

## 📊 Example Output

```
══════════════════════════════════════════════════════════════════════
 🔍 PySpectre - Advanced Formal Verification Report
    Interprocedural Analysis with Z3 Theorem Prover
══════════════════════════════════════════════════════════════════════

🔴 CRASHES PROVEN POSSIBLE (Z3 found counterexamples):
──────────────────────────────────────────────────────────────────────

  ➗ [DIVISION BY ZERO]
    🔴 mycode.py:12 in unsafe_divide()
       Division by zero: y can be 0 in //
       💡 Crash when: y=0

══════════════════════════════════════════════════════════════════════
 📊 Summary
══════════════════════════════════════════════════════════════════════
  📁 Files scanned:       5
  🔧 Functions analyzed:  23
  🔴 Potential crashes:   3
  ✅ Proven safe:         45
  🔗 Call relationships:  12
  ⏱️  Total time:          1.23s

  ❌ Found 3 potential crash(es) with mathematical proof!
```

## 🏗️ Architecture

```
pyspectre/
├── analysis/              # Analysis engines
│   ├── z3_engine.py       # Core Z3 verification (~1,700 lines)
│   ├── z3_prover.py       # Backwards-compatible API
│   ├── detectors.py       # Bug detectors
│   ├── taint_analysis.py  # Taint tracking
│   ├── bounds_checking.py # Bounds verification
│   └── ...                # 35+ analysis modules
├── core/                  # Core symbolic types
│   ├── types.py           # Symbolic value types
│   ├── state.py           # VM state management
│   ├── solver.py          # Z3 solver wrapper
│   └── ...                # 15+ core modules
├── execution/             # Bytecode execution
│   ├── executor.py        # Main executor
│   ├── opcodes/           # Opcode handlers
│   └── verified_executor.py
├── models/                # Built-in models
├── reporting/             # HTML/SARIF output
├── contracts/             # Design-by-contract
└── ...
```

### Key Components

- **Z3Engine**: Main verification engine with interprocedural analysis
- **SymbolicExecutor**: Full bytecode-level symbolic execution
- **CallGraph**: Tracks caller/callee relationships across functions
- **FunctionSummary**: Caches analysis results for efficiency
- **Detectors**: Pluggable bug detectors for various issue types

## 🧪 Running Tests

```bash
# Run all tests (1655 tests)
pytest tests/ -v

# Run specific test modules
pytest tests/test_z3_prover.py -v
pytest tests/test_interprocedural.py -v

# Run with coverage
pytest --cov=pyspectre tests/ -v
```

## 📋 CLI Options

```
usage: pyspectre_verify.py [-h] [--json JSON] [--verbose] [--timeout TIMEOUT]
                           [--quiet] [--call-graph] [--no-interprocedural]
                           [--no-taint] path

Formally verify Python code won't crash using Z3

positional arguments:
  path                  File or directory to scan

options:
  -h, --help            show help message
  --json, -j            Output JSON report to file
  --verbose, -v         Show proven safe items and timing
  --timeout, -t         Z3 timeout in ms (default: 5000)
  --quiet, -q           Only show crashes, no progress
  --call-graph, -g      Show call graph relationships
  --no-interprocedural  Disable interprocedural analysis
  --no-taint            Disable taint tracking
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request
