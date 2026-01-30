# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0-alpha] - 2026-01-30

### Added
- **61 new stdlib models**:
  - `pathlib`: Path(), exists, is_file, is_dir, name, stem, suffix, parent, joinpath, /, read_text, write_text, read_bytes, write_bytes, resolve, mkdir, unlink, glob, rglob (21 models)
  - `operator`: itemgetter, attrgetter, add, sub, mul, truediv, floordiv, mod, neg (9 models)
  - `copy`: copy, deepcopy (2 models)
  - `io`: StringIO, BytesIO, read, write, getvalue (5 models)
  - `heapq`: heappush, heappop, heapify, heapreplace, heappushpop, nlargest, nsmallest (7 models)
  - `bisect`: bisect_left, bisect_right, bisect, insort_left, insort_right, insort (6 models)
  - `enum`: Enum, IntEnum, auto, value, name (5 models)
  - `dataclasses`: dataclass, field, asdict, astuple, fields, replace (6 models)

- **Enhanced loop handling**:
  - Smart bound inference from SymbolicRange iterators
  - Induction variable detection (i += step patterns)
  - Loop summarization for closed-form computation
  - Improved loop invariant generation
  - Induction-aware widening with bound constraints

- **State merging improvements**:
  - Linking constraints to preserve condition-value relationships
  - Better precision for single-arm conditionals

### Changed
- Rebranded from "Shadow VM" to "PySpectre" throughout documentation
- Updated CLI to use `pyspectre` command

### Fixed
- Test patterns for symbolic division by zero detection
- State merger precision for merged value constraints

## [0.1.0-alpha] - 2026-01-24

### Added
- Initial release
- Symbolic execution engine with Z3 integration
- Bug detectors: division by zero, assertion errors, index errors, key errors, type errors
- Path exploration strategies: DFS, BFS, coverage-guided
- Output formats: text, JSON, HTML, Markdown, SARIF
- CLI interface
- Full type annotations
