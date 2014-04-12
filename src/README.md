-*- outline-mode -*-

This is a pre-release of miTLS, a verified reference implementation of
the TLS security protocol.

* 1. Compilation

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

* 2. Verification

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

* 3. Prerequisites

In the following, the prerequisites for each supported platform are
given. 

** 3.a. Microsoft Windows

- Cygwin, with the make utility installed
- .NET version 4 or above
- Visual F# 2.0
- Power Pack for F# 2.0

** 3.b. Linux, Mac OS X and other Un*ces

- Mono framework, version 3.0.1 or above
- F# open source edition, version 3.0 or above


## 4. HttpServer

Getting the HttpServer to run properly.

OS X

```
cd src
make
mkdir -p src/www-data/sessionDB src/www-data/www-root
cd www-data
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout localhost.pem -out localhost.crt
openssl pkcs12 -export -out localhost.crt.p12 -in localhost.crt -inkey localhost.pem 
certmgr -add -c -p default My localhost.crt.p12
mono ImportCert.exe localhost.crt
mono ../HttpServer/bin/Release/HttpServer.exe --root-dir www-root/ --sessionDB-dir sessionDB/ --local-name localhost
```

On windows, leave out 'mono' and import into 'Current User/Personal' and mark
the key as exportable. Then add the certificate to 'Trusted Root Certificate
Authorities' to have its chain work.

On OS X, to import the self-signed certificate into the trusted roots-store:

```
module ImportRootCert.Main

open System
open System.IO
open Mono.Security.X509

[<EntryPoint>]
let main args = 
    let certBytes = File.ReadAllBytes(args.[0])
    let rootCert = new X509Certificate(certBytes)
    let store = X509StoreManager.CurrentUser.TrustedRoot
    store.Import rootCert
    0
```

Compile in Xamarin Studio and pass the `crt` file (not the full pfx file) as the
first parameter.