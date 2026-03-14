# Contributing to AgentGuard

## Development Setup

1. **Prerequisites**: .NET 8.0 SDK or later
2. **Clone**: `git clone https://github.com/YOUR_USERNAME/AgentGuard.git`
3. **Build & Test**: `./eng/build.sh` (Linux/macOS) or `eng\build.cmd` (Windows)

## Project Structure

```
AgentGuard/
├── src/
│   ├── AgentGuard.Core/         # Abstractions, rules, pipeline, middleware
│   ├── AgentGuard.Local/        # Offline classifiers
│   ├── AgentGuard.Azure/        # Azure AI Content Safety adapter
│   └── AgentGuard.Hosting/      # DI registration, config binding
├── tests/                       # Unit + integration tests
├── samples/                     # Runnable examples
├── docs/                        # Documentation
└── eng/                         # Build scripts
```

## Adding a New Rule

1. Create a class implementing `IGuardrailRule` in `src/AgentGuard.Core/Rules/<Category>/`
2. Add a fluent method to `GuardrailPolicyBuilder`
3. Write unit tests in `tests/AgentGuard.Core.Tests/Rules/`
4. Update `docs/rules-reference.md`

## Code Style

- File-scoped namespaces, `var` where obvious
- Prefer `ValueTask` for guardrail evaluations
- XML doc comments on all public APIs
- No warnings in CI (`TreatWarningsAsErrors` is on)

## Pull Requests

1. Fork → feature branch from `main` → write tests → `./eng/build.sh` passes → open PR
