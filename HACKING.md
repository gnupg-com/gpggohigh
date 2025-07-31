# Hacking on `gpggohigh`

## Build against a recent GPGME library

You probably want to build gpggohigh against a recent `gpgme`library
which you build and installed yourself.
So make sure to use your own builds make sure to set the `LD_LIBRARY_PATH`
and `LD_PRELOAD` to point to your own build.
For example:

```bash
export LD_LIBRARY_PATH=${HOME}/usr/lib:$LD_LIBRARY_PATH
export LD_PRELOAD=${HOME}/usr/lib/libgpgme.so.11.33.1:${HOME}/usr/lib/libassuan.so.9.0.1
```

or use a bash script like this:

```bash
#!/bin/bash
LD_LIBRARY_PATH=$${HOME}/usr/lib:$$LD_LIBRARY_PATH \
GOAMD64=V2 \
CGO_CFLAGS="-I$${HOME}/usr/include" \
CGO_LDFLAGS="-L$${HOME}/usr/lib" \
CGO_ENABLED=1 \
go build -v -trimpath $*
```

## Test

To run the tests, you need to have a GPG keypair available.
To log GPGME activity, you can set the `GPGME_DEBUG` environment variable to '9'
and specify a log file.
For example:

```bash
GPGME_DEBUG=9:/tmp/gpapp_gpgme.log:  ./text-sig h@g
```
