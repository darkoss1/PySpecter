# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0-alpha] - 2026-01-24

### 🚀 Released
- Initial public release as an **Educational Prototype**.
- **Symbolic Execution Engine**: Implemented `VMState` and `SymbolicExecutor` for bytecode analysis.
- **Z3 Integration**: Core `Z3Engine` for mathematical verification of path constraints.
- **Abstract Interpretation**: Added Interval and Sign domains for loop approximation.
- **Detectors**:
  - Division by Zero
  - Assertion Errors
  - Index Out of Bounds
  - Type Errors
- **Reporting**: Beautiful HTML and Text reporters.

### ⚠️ Disclaimer
- Downgraded status to **Alpha**.
- Explicitly labeled as **Educational Purpose Only** to prevent production misuse.
- Not audited for security critical applications.
