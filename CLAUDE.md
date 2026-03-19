# SentinelLog

A CLI-based log analyzer and threat detector for portfolio use.

## Stack
- Python 3.11+
- pytest for all tests (TDD strictly)
- Type hints on every function
- Click for CLI interface
- Rich for terminal output formatting

## Project Goal
Analyze server/auth logs and surface threats:
- Brute force login attempts
- Port scanning patterns
- Suspicious IP activity
- Failed sudo attempts

## Rules
- Write failing tests BEFORE implementation (TDD)
- Every detector module gets its own test file
- No hardcoded IPs or paths — config driven
- All public functions must have docstrings + type hints

## Security Note
This tool is for defensive analysis only — logs the user owns.
