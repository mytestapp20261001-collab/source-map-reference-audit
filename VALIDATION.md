# Validation record

Validated locally on 2026-10-09 with CPython 3.12.14 and 3.13.5 on Linux.

- `python3 -m unittest -v test_tool.py`: 19 tests passed on each Python version.
- `python3 examples/run_examples.py`: two real CLI calls passed their expected exit-code/status checks (0/pass, 1/findings).
- `python3 tool.py --help`: exit 0.
- Invalid CLI arguments: exit 2, one sanitized JSON error, no traceback.
- All four Python source files parsed successfully using the standard-library AST parser.

Tests use synthetic local temporary files. Permission-error paths are covered by unittest mocks and independent CLI checks against synthetic mode-000 inputs under a non-root Linux user; this is not evidence of a production restricted-filesystem deployment. Linux/POSIX is the tested runtime. Windows/macOS execution and hostile concurrent filesystem mutation were not tested; unsupported no-follow runtimes fail closed. See README.md for policy scope and deliberate limitations.

Independent regression checks also cover nonlocal sources hidden behind sourceRoot, independent sourceRoot validation, and valid relative parent references.
