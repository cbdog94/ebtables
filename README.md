ebtables
============

[![Latest release][release_badge]][release_url]

Introduction
---

This repo modified the ebtables for supporting some custom features. Compared with the original version, it mainly added comment, dset and ipset extensions.

The modified parts are listed below:
```
├── extensions/
│   ├── ebt_comment.c
│   ├── ebt_dset.c
│   ├── ebt_set.c
│   └── Makefile
└── include/
    └── linux/
        └── netfilter_bridge
            ├── ebt_dset.h
            └── ebt_set.h
```
Installation instructions for ebtables
---

ebtables uses the well-known configure(autotools) infrastructure.
```
	$ ./configure
	$ make
	# make install
```

Prerequisites
---
* no kernel-source required
* but obviously a compiler, glibc-devel and linux-kernel-headers (/usr/include/linux)

Configuring and compiling
---

./configure [options]

--prefix=

The prefix to put all installed files under. It defaults to /usr/local, so the binaries will go into /usr/local/bin, sbin, manpages into /usr/local/share/man, etc.

If you want to enable debugging, use
```
./configure CFLAGS="-ggdb3 -O0" CPPFLAGS="-DEBT_DEBUG"
```
(-O0 is used to turn off instruction reordering, which makes debugging much easier.)

 [release_badge]: https://img.shields.io/github/release/cbdog94/ebtables.svg
 [release_url]: https://github.com/cbdog94/ebtables/releases/latest