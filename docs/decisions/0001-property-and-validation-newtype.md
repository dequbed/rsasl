# Using a `const`-able newtype for Properties and Validations

* Status: accepted <!-- optional -->

Technical Story: rsasl needs a zero-overhead way of matching requested properties and validation in callbacks <!-- optional -->

## Context and Problem Statement

Rsasl needs to request data and actions from user codes using callbacks. These callbacks are used
via trait objects so the can not use generic types the way their `Session` counterparts do.
Specifically this validation/property type needs to be passed as parameter. Additionally the number
of properties and validations can be extended by downstream crates that implement additional
mechanisms, so there is no complete list we could have while writing rsasl, but there is a
complete list while compiling rsasl.

Whatever this type should be they need to be ergonomic to use which in the case of Rust includes
being able to `match` on them.
To this end there must exist `const` values of these types since you can not `match` on function
results.
Additionally these traits can not contain *references* to trait objects and must implement
`PartialEq` and `Eq`. `*const dyn TraitObject` do work.

## Decision Drivers <!-- optional -->

* Need to be able to `match` on a type that may be extended by downstream crates
* Match should be type-safe, so no way to match a `validation` where a `property` is expected.

## Considered Options

* `std::any::TypeId` in a `struct Newtype(..)` wrapper
* `*const dyn Validation` and `*const dyn Property`
* Composite struct type with very low expected collision chance.
* a proc macro adding an attribute that will assign a unique id to each invocation

## Decision Outcome

Chosen option: "Composite struct type", because on current stable it is the only solution not
requiring potentially brittle proc macro hacks and doesn't require downstream crates to define
several const values per Property/Validation.

### Positive Consequences <!-- optional -->

* Rather simple to implement downstream, just a `const PROP: Property = Property::new(&PropertyDefinition::new(...))`
* The match algorithm can be adjusted rather easily without breaking downstream crates

### Negative Consequences <!-- optional -->

* Collisions can't be checked by the compiler
* Code optimizer sees these values as very similar and may decide to unify them.

## Pros and Cons of the Options <!-- optional -->

### `std::any::TypeId`

The basic mechanism we want already exists as
[`std::any::TypeId`](https://doc.rust-lang.org/std/any/struct.TypeId.html).

* Good, because no further code required
* Good, because obvious to users
* Good, because final value can be known to the compiler (and is in current implementation a u64
  that will have very close values for all Properties/Validations in a crate) and the `match` can
  thus be optimized easier.
* Bad, because [`TypeId` can't be constructed `const` on stable rustc](https://github.com/rust-lang/rust/issues/77125), 
  making the use of `match` impossible.

### *const dyn Validation

Create newtype wrappers around const ptrs to trait objects and match on the ptr value.

* Good, because compiler must generate separate values thus guaranteeing collision avoidance.
* Bad, because final value can't be known at compile time so matches can't optimize well
* Bad, because for each Property and Validation two const values have to be created: The Trait
  object itself and the ptr to it.
* Bad, because calling the `Debug` and `Display` implementations will always require `unsafe`.

### Composite structs containing info

Simply create a struct containing a human-readable name and description for the Property/Validation
and make use of the fact that they are very likely going to be different.

* Good, because very simple and understandable for downstream crates
* Bad, because collision avoidance depends on strings
* Bad, because equality is matched over strings and thus much slower than a simple integer
  comparison, and can also not easily be optimized into a jump table.

### Proc macro assigning ids

Write a proc macro that assigns IDs.

* Good, because it gives all the advantages of `TypeId` but can be created in `const` contexts.
* Bad, because it makes this proc macro a rather hard requirement. Proc macros are potential security
  issues and may be forbidden in some situations.
* Bad, because it has to rely either on brittle solutions like creating a file in `target/` tracking
  the current ids which especially given incremental compilation is hard to get right, or
  alternatively use a hash algorithm like sha that generates big numbers that also do not optimize
  into a jump table.
