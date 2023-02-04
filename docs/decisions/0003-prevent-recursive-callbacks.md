# Prevent recursive calls in property request methods

* Status: accepted <!-- optional -->
* Deciders: dequbed <!-- optional -->
* Date: 2023-01-30 <!-- optional -->

See also the [Github issue]

## Context and Problem Statement

Right now there is a potential issue with Callbacks that need to aquire locks; if a mechanism calls `session.need_with` and friends from within the closure of `session.need_with` a second call to `Callback::callback` will be issued before the first one completes. If e.g. a Mutex is aquired inside the first function call it will likely not be released by the second call, leading to a deadlock.
We should either explicitly document Callbacks not being allowed to hold locks over a call to `provide` or prevent mechanism from calling `need_with` recursively.

The latter can easily be done via type system by making `need_with` take `&mut self,` the latter is likely much harder and potentially worse from an user perspective.

## Decision Drivers <!-- optional -->

* Implementations of mechanisms know very little about their uses and are supposed to be as plug-and-play as possible; issues like the above can lead to hard-to-debug interaction bugs.

## Decision Outcome

Chosen option: "Prevent recursive callbacks", because the compiler can more easily enforce this rule: by taking a `&mut self` in the MechanismData property methods recursive calls are prohibited.

### Positive Consequences <!-- optional -->

* A number of interaction bugs and edge-cases are prevented
* Developers are informed of improper use right away by descriptive compiler messages

### Negative Consequences <!-- optional -->

* A number of optimizations to forgo allocation and memory copying aren't possible since the lifetimes or provided properties does not extend outside the callback. For example it's not possible to request a value for `OverrideCBType` and request the cb data from within the response callback.

## Pros and Cons of the Options <!-- optional -->

### Prevent recursive callbacks

* Good, because it prevents interaction bugs
* Bad, because it prevents a number of small optimization and will force more allocations
* Neutral, it's additionally always possible to drop this restriction again as going `&mut self -> &self` is not a breaking change.

### Allow recursive callbacks

* Good, because it allows for some optimizations
* Good, because it minimizes the limits the rsasl API forces upon mechanisms
* Bad, because it increases the chance of deadlocking
* Bad, because while it minimizes limits it does so by putting further assertions on callbacks that are not immediately obvious from the API and function prototypes.

## Links <!-- optional -->

* [Github issue]

[Github issue]: (https://github.com/dequbed/rsasl/issues/18)