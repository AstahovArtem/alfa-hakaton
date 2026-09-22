# pdn-shield — conventions

- Go 1.26, stdlib + gopkg.in/yaml.v3 only. Ask before adding any other dependency.
- Layout: cmd/pdn-shield (entrypoint), internal/pii (core), internal/pii/detectors (detectors), configs/ (yaml).
- Every detector is a plugin: implements pii.Detector and registers itself in the Registry. Adding a PII
  type must never require editing pipeline/resolve code.
- Regex-based types live in detectors/rules.yaml; only complex types (names, dates in words, addresses)
  get dedicated Go detectors.
- Never log or print raw PII values. Logs and errors carry only categories, counts and positions.
- Never commit secrets. .env is git-ignored.
- All code and comments in English. Test data may be Russian.
- Run `make vet test` before finishing any task. gofmt must be clean.
- Tests are table-driven. Each detector has positive cases, negative cases (false-positive traps) and
  case-insensitivity cases.