## 0.0.1, 2025-15-02

### New Features
- Support `encoding.BinaryAppender` for `ECHConfig` and `ECHConfigList`.

### Chore
- Add a test to ensure compatibility with go stdlib.
- Add `stdlib` and `cfgo` examples.

### Bug Fixes
- Fix `ECHConfig` serialization logic to meet the specs [#1](https://github.com/OmarTariq612/goech/issues/1).

### Breaking Changes
- Fixing `ECHConfig` serialization logic introduced breaking changes for `MarshalBinary`, `UnmarshalBinary`, `ToBase64` and `ToBase64OrPanic`.
- `GenerateECHKeySet` accepts `CipherSuites` slice as an additional parameter. It can be set to `nil` to add all supported cipher suites.
- `GenerateECHKeySet` returns a `ECHKeySet` value instead of a pointer.
- `UnmarshalBinary` for `ECHConfig` now overwrites the underlying `CipherSuites` slice instead of allocating every time `UnmarshalBinary` is called.