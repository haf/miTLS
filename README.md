# miTLS

miTLS is a verified reference implementation of the
[TLS protocol](http://tools.ietf.org/html/rfc5246). Our code fully
supports its wire formats, ciphersuites, sessions and connections, re-handshakes
and resumptions, alerts and errors, and data fragmentation, as prescribed in the
RFCs; it interoperates with mainstream web browsers and servers. At the same
time, our code is carefully structured to enable its modular, automated
verification, from its main API down to computational assumptions on its
cryptographic algorithms.

Our implementation is written in [F#](http://fsharp.org/) and specified in
[F7](http://research.microsoft.com/en-us/projects/f7/). We present security
specifications for its main components, such as authenticated stream encryption
for the record layer and key establishment for the handshake. We describe their
verification using the F7 refinement typechecker. To this end, we equip each
cryptographic primitive and construction of TLS with a new typed interface that
captures its security properties, and we gradually replace concrete
implementations with ideal functionalities. We finally typecheck the protocol
state machine, and thus obtain precise security theorems for TLS, as it is
implemented and deployed. We also revisit classic attacks and report a few new
ones.

[See miTLS in action](https://www.mitls.org/)!

## TLS

TLS is possibly the most used secure communications protocol, with a 18-year
history of flaws and fixes, ranging from its protocol logic to its cryptographic
design, and from the Internet standard to its diverse implementations.


This is a pre-release of miTLS, a verified reference implementation of
the TLS security protocol.

## 1. Compilation

To compile, usually running "make" from the top level directory is
enough. (See below for prerequisites.)

The produces executables are placed in the `bin' directory.

Each command line tool accepts a "--help" option that shows all the
available command line options and their default values.

The following make targets are available:

- build (default)
    compiles source code and puts executables in then bin directory

- dist
    prepares a compressed archive that can be distributed

- dist-check
    as dist, but also performs some sanity checks

- clean
    remove object files

- dist-clean
    remove object files and distribution archives

The test suite is currently not released, and thus not
available as a make target.

## 2. Verification

Refinement type checking of the code base is driven by the Makefile in
./lib; this file has a "tc7" target for each file to be type checked.
Type checking requires F7 and Z3. Note that the latest version of F7
we use is currently not released.

Each F# implementation file (with .fs extension) may use compilation
flags to control what is passed to F7 vs F#

- ideal: enables ideal cryptographic functionalities in the code.
  (e.g. the ones performing table lookups)

- verify: enables assumptions of events in the code.

Both compilation flags are disabled when compiling the concrete code,
and enabled during type checking.

## 3. Prerequisites

In the following, the prerequisites for each supported platform are
given. 

### 3.a. Microsoft Windows

- Cygwin, with the make utility installed
- .NET version 4 or above
- Visual F# 2.0
- Power Pack for F# 2.0

### 3.b. Linux, Mac OS X and other Unix-es

- Mono framework, version 3.0.1 or above
- F# open source edition, version 3.0 or above

