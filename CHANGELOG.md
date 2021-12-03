# Revision history for `rsasl`

## 1.0.0 — 2021-04-06 

* Initial stabilized release

## 1.2.0 — 2021-10-02

* `SaslError` marked `Eq` and `Ord`
* Fixes a null-pointer panic when passing invalid SaslErrors

## 1.3.0 — 2021-10-02

* Improved error messages

## 1.4.0 — 2021-10-09

* Usability improvements with better type aliases

## 1.4.1 — 2021-10-20

* Fixes potential bad pointer conversion on non-x86 targets

## 2.0.0-preview — 2021-12-03

* Preview release for the pure-Rust version
* Big thanks to all [c2rust contributors](https://github.com/immunant/c2rust/graphs/contributors) making this release
  possible