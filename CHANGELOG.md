# Changelog

## 3.1.0 (2026-01-27)


### ⚠ BREAKING CHANGES

* github.com/pascaldekloe/jwt@1.2.0 incompatible with go1.10.

### Features

* added Audiences string slice to result, audience compare is now case-sensitive, result.Audience is derived from RSAVerifier.Audience in `RSAVerifier` ([a81c07b](https://github.com/na4ma4/jwt/commit/a81c07b57389d1e15befcd52fb9f0766dcfb3328))
* removed go1.10 from travis build ([284cdc9](https://github.com/na4ma4/jwt/commit/284cdc93c5963ec8e0953188c143adc79d714ac1))
