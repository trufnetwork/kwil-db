# Dependency Management

Dependencies are integral to software development, offering reusable code to
solve common problems, thereby accelerating development cycles. However, they
can also introduce risks and complications, from maintenance challenges to
security vulnerabilities. This can be particularly problematic in Go projects
where module version resolution is influenced by all of a projects dependencies,
including indirect dependencies.

When a dependency is essential, we need to ensure it's reliable, secure,
well-maintained, an appropriate for a given context (e.g. tests vs.
consensus-critical code). This document provides guidance for dependency
management in Kwil DB.

## Semantic Import Versioning (SIV) in Go

Go's dependency management tool, Go Modules, uses the concept of [Semantic
Import Versioning (SIV)](https://research.swtch.com/vgo-import) to handle
versioning issues. It mandates that module paths change as the major version of
the module changes, if there are breaking changes. However, it is often followed
loosely or entirely flaunted, even by widely used projects.

### Breaking Changes Increase the Major Version

Examples of breaking API changes include when an exported function signature
changes, or an exported struct has a field removed or renamed, etc. Adding new
functions, methods, or fields are generally not breaking changes.

For example, if a module at `example.com/module` is at version 1, and there is a
breaking change, it should become version 2 and it would be imported as
`example.com/module/v2` (with a revised module name in its `go.mod`).

See the [Go Modules Reference](https://go.dev/ref/mod#versions) for more
information.

**NOTE:** This is a main reason why it is important to minimize our own public
API surface by unexporting and utilizing `internal` packages for things that we
only intend to be used within our project.

### v0 Project Status

Also note that projects with their major version at 0 in revision control semver
version tags (e.g. `v0.5.1`) are considered to have unstable APIs, and there are
no promises of stability as described above. This is necessary for early stage
and rapidly evolving projects. We should strive to reach v1, but not before we
are ready to commit to a stable Go API.

## Handling Transitive Dependencies

### Go's Version Resolution System

Transitive dependencies are libraries that our direct dependencies rely on.
These can exponentially increase the number of dependencies.

Minimal Version Selection (MVS) is Go’s mechanism for resolving version
conflicts. When faced with multiple versions of the same module across
dependencies, Go picks the *highest* version among the minimum required versions
of that module.

For example, if we require version 1.2.3 of a certain module, and one of our
dependencies requires version 1.3.0, Go’s MVS will resolve this conflict by
selecting version 1.3.0.

This means we can end up using a newer version of a module than we explicitly
specified if one of our dependencies requires it. This can be trouble if a
module does not respect semantic versioning by making no breaking API changes
within a given major version, as described in the previous section.

As such, we should strive to minimize the total number of dependencies, and avoid those that flaunt semantic versioning.

## Contexts for Accepting Dependencies

Accepting a dependency is more justifiable in the following scenarios:

### Non-Trivial Solutions

If the library solves a complex problem that would be require notable development time to implement in-house. Evaluate whether a dependency truly offers significant benefits and whether the functionality can be efficiently implemented in-house.

Before exploring external libraries, exhaust the possibilities within Go’s extensive standard library.

### Scope of Use

Consider the context in which the dependency will be used. If its use is limited to testing or non-critical parts of the application, the risks associated might be more acceptable.

Dependencies used solely in testing are generally less risky, as they don’t affect the final production build. However, this still end up listed in go.mod.

### Adherence to SIV

Examine release history to ensure the dependency follows semantic versioning.
Look for consistent major version bumps when breaking changes are introduced. If
the module is v0, this implies it does not.

### Transitive Dependencies

Libraries with no or fewer transitive dependencies are preferable as they introduce less complexity and risk.

### Active Maintenance

Check the activity and maintenance status of the dependency. An actively
maintained library is usually more reliable.

### License

Ensure the license of the dependency is compatible with Kwil DB's license.
Generally this means ensuring a permissive license, and avoiding most GPL
flavors when possible. We are offering an SDK to developers, and we do not want
to place *any* unintended encumbrances on its use.

## Appendix

### Checking Resolved Versions

We can use the `go list` command to view the selected versions of our
dependencies:

```shell
go list -m all
```

This command lists all the current module’s dependencies and the versions that
will be used to build it, as resolved by MVS.

### Tracing Dependencies

The `go mod why -m` command is an essential tool in understanding how a
dependency was introduced into our `go.mod` or `go.sum` files. It displays the
shortest path from a package in one of our modules to a given module. Here’s a
practical example:

Suppose we have a dependency listed in `go.mod` as:

```plaintext
github.com/example/dependency v1.2.3
```

To investigate how this dependency was introduced, you would run:

```plaintext
go mod why -m github.com/example/dependency
```

The output will show the shortest path of import statements, leading from a
package in our main module to a package in github.com/example/dependency. This
helps us understand why the dependency is included and which part of the code
relies on it.

```plaintext
# github.com/example/dependency
(main module)
github.com/trufnetwork/kwildb
github.com/anothermodule/anotherpackage
github.com/example/dependency
```

This output signifies that kwildb imports anotherpackage, which in turn imports
the dependency. If the `go mod why -m`` command indicates that the dependency is
not explicitly used by our code, it might be a transitive dependency, brought
in by another module we are using.
