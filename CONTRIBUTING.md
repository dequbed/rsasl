# Contributing to rsasl

First: If you are unsure or afraid of *anything*, just ask or submit the issue or pull request anyway. You will not be
yelled at for giving it your best efford. The worst that can happen is that you'll be politely asked to change
something. We appreciate any sort of contributions, and don't want a wall of rules to get in the way of that.

rsasl welcomes contributions from everyone. Here are the guidelines if you are thinking about helping us:

## Contributions

Contributions to rsasl should be made in the form of GitHub Pull Requests. 

Issues that we think are easy to get started on are marked with the label ["good first issue"](https://github.com/dequbed/rsasl/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
These issues will generally also contain a sentence or two on the reasons why this issue is considered a good first issue.

Should you want to work on an issue please claim the issue first by commenting that you want to work on it. This is 
to prevent duplicate work on the same issue. If somebody else is already working on an issue they may be happy to work 
together with you too!

### Pull Request checklist

- Branches should branch from the `development` branch, unless the PR is about fixing a bug or some high-priority issue.
  If needed, rebase your branch to the current `development` before submitting your PR. If a PR can not be merged 
  cleanly you may be asked to rebase your changes.
- Commits should be accompanied by a Developer Certificate of Origin (https://developercertificate.org/) to indicate 
  that you (and your employer if applicable) agree to be bound by and release your changes under the 
  [licensing terms](README.md#license) of the project. 
  
  In git the certificate can easily be added by using `git commit -s` to commit.

- To make bisecting issues easier commits should be small but independent (i.e. compile and be testable). A good 
  guideline for commit size is in fact the smallest set of changes that compiles and passes tests. If a change 
  affects a hundred files, a 'small' commit can very much span all those hundred files.

- rsasl uses a merge-focused workflow. Rebases should only happen to update a feature branch to the latest upstream 
  development or similar. Additionally, please do not squash a PR into a single commit unless it is a very small change.

## Release workflow

`rsasl` has a release workflow based on [`gitflow-avh`](https://github.com/petervanderdoes/gitflow-avh) and [crateci's `cargo-release`](https://github.com/crate-ci/cargo-release).

1. Make sure you have the required git-hook installed and marked executable. The release process specifically requires the file [tools/pre-release.sh](tools/pre-release.sh) to be installed as `.git/hooks/pre-release.sh`.
2. `cargo release [level]` where `level` defines what version number to bump to and is [further described in the cargo-release reference](https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md#bump-level).
   - This will perform a *dry-run* and not make or commit any changes. Use it to verify that everything will happen as intended.
3. `cargo release -x [level]` to perform the release. This will drop you on a new `release/[new version]` branch with changes to the Cargo.toml and CHANGELOG.md already added to be committed.
   1. Verify everything that needs to be included for the release is included.
   2. Run any pre-release tests and checks
   3. Finalize the release with `git flow release finish`. This will merge all branches as required and drop you into an editor to finalize the tag name and description.
4. Push the `development` and `main` branch, and the newly created tag upstream: 
   - `git switch main && git push`
   - `git switch development && git push`
   - `git push --tags`

