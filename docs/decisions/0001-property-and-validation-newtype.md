# Properties and Validations

* Status: accepted <!-- optional -->

Technical Story: rsasl needs an efficient and easy to use way of matching requested properties and validation in 
callbacks <!-- optional -->

## Context and Problem Statement

Rsasl needs to request data and actions from user codes using callbacks. These callbacks are used
via trait objects so they can not use generic types the way their `Session` counterparts do.
Specifically this validation/property type needs to be passed as parameter. Additionally, the number
of properties and validations can be extended by downstream crates that implement additional
mechanisms, so there is no complete list we could have while writing rsasl, but there is a
complete list while compiling the final application.

## Decision Drivers <!-- optional -->

* protocol and mechanism implementations, and the final users of rsasl should be exposed to as little implementation 
  detail of each other as possible.
* Properties must be freely extensible but type-safe to use so that additional mechanisms can be implemented.

## Considered Options

* Opaque Newtype using `core::any::TypeId`
* Opaque Newtype using `*const dyn Validation` and `*const dyn Property`
* Composite struct containing (static) information
* Proc macro adding an attribute that will assign a unique id to each invocation, then checking that

## Decision Outcome

Chosen option: "opaque Newtype using `core::any::TypeId`", because it is open-ended in extensibility yet hides every 
implementation detail thus also allowing to upgrade to a different scheme if required later.

### Positive Consequences <!-- optional -->

* Trivial to implement, new Property types need merely to `impl Property`
* Allows not having to transfer ownership in certain cases, preventing heap allocations
* Type-safety is easily and to the user transparently enforced, with Properties defining a value type that must be 
  passed
* `impl Properties` are very abstract and can be easily reused for mechanism context

### Negative Consequences <!-- optional -->

* Use of `match` is not possible
* Checking if all required properties are handled is less obvious to developers
* implementing 

## Pros and Cons of the Options <!-- optional -->

### Opaque Newtype using `core::any::TypeId`

`TypeId` resp. `Any` is the compiler-supported way to add RTTI, see the 
[module documentation for `core::any`](https://doc.rust-lang.org/core/any/index.html).

* Good, most flexible option as implementation details and hidden and can be freely modified
* Good because all `unsafe` code is hidden from the user
* Bad because `unsafe` is required in the backend to cast the type-erased properties

### Opaque Newtype using `*const dyn Validation` resp. `*const dyn Property`

* Good because as above implementation details are hidden and can be modified
* Bad, implementation of properties is more complicated as the `Validation` and `Property` traits would have to do 
  additional lifting instead of just defining the Value type transported.
* Bad, properties would have to define `const` values to `match` against
* Bad, raw pointers will always require `unsafe` code to handle

### Composite structs containing info

Simply create a struct containing a human-readable name and description for the Property/Validation
and make use of the fact that they are very likely going to be different.

* Good, because very simple and understandable for downstream crates
* Bad, because collision avoidance depends on strings
* Bad, because equality is matched over strings, thus much slower than a simple integer comparison as done with `TypeId`

### Proc macro assigning ids

Write a proc macro that assigns IDs.

* Good because it gives most advantages of `TypeId` but can be created in `const` contexts.
* Good because assigned IDs can be assigned in order allowing the compiler to optimize a match to a jump table
* Bad because it makes this proc macro a rather hard requirement. Proc macros are potential security
  issues and may be forbidden in some situations.
* Bad because it has to rely either on brittle solutions like creating a file in `target/` tracking
  the current ids which especially given incremental compilation is hard to get right, or
  alternatively use a hash algorithm like sha that generates big numbers that also do not optimize
  into a jump table.
