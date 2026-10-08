# 📖 Documentation

release-gate is the independent admission controller for AI systems. It combines
code-level agent risk, external evaluations, runtime traces, governance evidence,
verification results and human approvals into an auditable PROMOTE / HOLD / BLOCK
decision, without requiring teams to replace the tools that produced the evidence.

## Start here

- **[QUICKSTART.md](QUICKSTART.md)**: decide a release in five minutes, then your own.

- **[POSITIONING.md](POSITIONING.md)**: what release-gate claims, what each claim
  rests on in code, and the six things it will not say. Read this before quoting the
  project anywhere.

- **[INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)**: how evidence from the tools you
  already run reaches the decision, and the decision reaches your pipeline.

## Reference

- **[REFERENCE.md](REFERENCE.md)**: every command and flag, the policies, the
  Admission Report, and the optional semantic verification.

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: how the engine is put together.

- **[specs/universal-assurance-architecture.md](specs/universal-assurance-architecture.md)**:
  the assurance architecture: the epistemic status calculus, the coverage model, the
  decision path, the migration record, and every defect found building it.

- **[RULES.md](RULES.md)**: the rule catalogue of release-gate's own agent-code
  scanner, one evidence producer among the others.

- **[EXTENDED_README.md](EXTENDED_README.md)**: the governance-file lane and the pull
  request gate in depth.

## Development & Contributing

- **[DEVELOPMENT.md](DEVELOPMENT.md)**: set up a development environment.
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: report bugs, suggest features, submit code.
- **[CHANGELOG.md](CHANGELOG.md)**: what changed in each version, with migration notes.

## Questions?

Open an issue on GitHub, or check closed issues for similar questions.
