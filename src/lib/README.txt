Main abstract types for modular cryptography
[TODO: document their qualified names & indexing]

"abstract" does not exclude plain/repr functions.

- all key types (and seeds, pms, ms) are abstract 
  must be strict before applying their crypto assumptions
  we may coerce before applying other assumptions,
  e.g. key exchange and key derivation.

- our modelling of plaintext secrecy for encryptions
  relies on nested abstract types: each "plain" is 
  itself implemented partly from the "plain" above
  * top-level plain for the TLS application
    - AppDataPlain.appdata; appdata/appdataBytes
	- Other functions (e.g. estimateLength) to prove auxiliary properties (e.g. Length hiding)
  * plain for appdata (and possibly other protocols)
    - AppDataPlain.fragment; fragment/repr
	- Other function to concatenate/split with AppDataPlain.appdata
  * plain for LHAE (= dispatch fragments)
    - TLSFragment.fragment; fragment/repr
	- Other functions to go from/to Plain.plain and PlainMAC.plain
  * plain for raw encryptions
    - Plain.plain; plain/repr
  must be strict for proving the main secrecy theorem
  for top-level plaintexts indexed by secure sessions/connections

- in EtM, we need auxiliary abstract types
  * for MACs computed partly on Dispatch.fragment
    - MACPlain.plain; plain/repr
  * for some of their concatenations

- we casually use abstraction for modularity, e.g.
  * all other content types are abstract---even ccsFragment---
    for uniformity, and in case we need to prove more secrecy later
  * internal control- and data-state are abstract (in handshake, dispatch, record...)
  * certs are abstract
  * ciphersuite is abstract (maybe unnecessary)

===============================


Here is the structure and current status of our TLS library,
(to be described in tls-f7.pdf once reasonably stable)
generally there are 3 files {fs7,fsi,fs}

--- external dependencies? 

Data			vs cma/lib? others?
Bytearray

AP: I'd like to get rid of both, and have a consistent one, where length is adequately supported.

--- TLS lib --- 
(see also doc/arch.pdf) 

Error			error handling and constants for TLS
TCP				networking (reliable but untrusted)

Cert				X.509 certificates

TLSConstants		identifiers and lengths used by TLS;
                TODO: sync lengths with some .fs7! 
				CF would prefer to split it between ENC, HMAC, etc. AP: Fine with me

Ciphersuites	data structures and functions from suite to algorithms
				use patterns instead of isNullCipherSuite etc?
				AP: One goal was to keep the type abstract, hence the functions. Keeping the
				type abstract syntactically avoids me any mistake. (Other option, which I don't like:
				two layers: pattern at external layer for things that are not abstract, and
				internal abstract layer. Too much hassle to code with this)

formats			? Defines CT plus some generic library stuff, not great. AP: Agree

TLSInfo			indexing for keys and sessions, plus user-customizable protocol behavior, which captures partially specified parts (MAY) of the RFC.

HASH
HMAC			mac algorithms, used only in MAC
MAC				parametric MACs for TLS

TLSPlain		high-level part of the TLS record protocol (defining secrets)
				TODO: have an abstract interface for it.

ENC				encryption algorithms --- not verified
				we may add a verification-only implementation of CBC
				parameterized by a PRP block-encryption algorithm.

LHAE			authenticated encryption with additional data
				implemented as MtE and (soon) GCM

Stream			where does it currently fit? AP: Nowhere, being replaced by TLSPlain, and some theorems
			about multiplexing (TODO)

record			low-level part of the TLS record protocol (below encryption)
				implementing stateful LHAEAD, dealing with headers and sequence numbers

PRFs			PRF used on MS and PMS

SessionDB		session management
				There is also some Sessions, ignored for now. AP: Sessions is to be deleted, replaced by TLSInfo

Handshake		handshake protocol handlers
				for now we primarily support 
				CipherSuite (RSA, MtE (AES_128_CBC, SHA))

Alert			alert and waring protocol handlers

AppData			application data protocol handlers
				there is also some AppData_stream, ignored for now: AP: can delete, it's the old (almost typechecking)
				version of AppData using streams, instead of TLSPlain

Dispatch		TLS connection logic & multiplexing

TLS				main API