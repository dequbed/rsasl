# Using `Property::Value` indirection over direct value access 

* Status: accepted
* Deciders: dequbed
* Date: 2022-08-01

## Context and Problem Statement

rsasl requires open polymorphic generic access to values for properties set by mechanisms as they need to be 
accessed by downstream code in their `Callback`. A similar system is at the time developed in the rust std as 
[std::any::Provider].
The decision to be made was wether to use direct value access similar to `Provider` i.e. `get<T>` returning a `&T`, 
or have an indirection, so `get<T: Property>` returning a `&T::Value`.

## Considered Options

* `provide_any` style direct value access
* `trait Property` based value indirection

## Decision Outcome

Chosen option: "`trait Property` based value indirection", because many properties make sense to have return the same 
type and this minimized the amount of newtype wrappers.

### Positive Consequences

* Properties are unit structs
* Property values do not need to be newtype-wrapped

### Negative Consequences 

* The system can not be later adapted to `provide_any`

## Pros and Cons of the Options 

### `provide_any` style direct value access

* Good, because it will be adapted into the Rust `std`, so is better known to users.
* Bad, because multiple values of the same type can not be stored, forcing the use of newtype wrappers.

### `trait Property` based value indirection

* Good, because it does not force newtype wrappers
* Good, because it allows additional features such as a descriptions being attached to `Property`
* Bad, because the system is more complex to understand than `provide_any`

## Links

* [std::any::Provider]
* [provide_any stabilization issue](https://github.com/rust-lang/rust/issues/96024)

[std::any::Provider]: https://doc.rust-lang.org/std/any/trait.Provider.html