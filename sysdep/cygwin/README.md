
# BIRD on Windows/Cygwin

## Building

To buil BIRD for Windows you need cygwin environment. Visit
[cygwin.com](https://cygwin.com) and download installer.

### Required packages

The cygwin installer works as package manager. Keep packages selected by default
and add following packages: `autoconf make gcc-core flex bison libncurses-devel libreadline-devel`

### Compilation

BIRD for cygwin is built almost the same way as for Unix platforms. Open cygwin
terminal and:

    $ cd $BIRD_SRC
    $ autoconf
    $ ./configure
    $ make

There are couple of small differences. Default prefix is set to `C:/bird`. To
use different prefix add option `--prefix=C:/cygwin/bird`. This prefix is used
for all paths of bird. Meaning that pid file, default config files search
location and unix socket are in this directory.

Second, you don't do `make install`. Just copy compiled binaries (the .exe
files) to your desired destination.

### Running

To run BIRD on Windows you must first copy Cygwin DLLs to system. Copy them from
cygwin binaries directory (by default `C:/cygwin64/bin`). You need
`cygwin1.dll`, `cygncursesw-10.dll` and `cygreadline7.dll`. Later two are needed
by `birdc`. If you're happy with lite client `birdcl`, you can omit them. Copy
them to Windows system directory (usually `C:/Windows/System32` but generally
`%SYSTEMROOT%/System32`).

Cygwin isn't needed to run BIRD. You only need those DLLs in system.

Note: BIRD must be started with Administrator privileges.

## Configuration

When editing BIRD's config files on Windows keep in mind how Windows name
it's network interfaces. Each NIC has 2 names. Friendly name and ID. Friendly
names are those you see when you type `ipconfig`. These can be changed and so
aren't suitable for use in configuration.
BIRD works with IDs. You can list them by following commands:

    sc start dot3svc
    netsh lan show interaces

and for wirelles adapters:

    sc start wlansvc
    netsh wlan show interaces

field `GUID` is the ID. But it must be inclosed in curly brackets. For example:

    protocol rip {
      interface "{C268783F-F5FC-465E-B9F9-BAA590D27BB2}" {
        mode multicast;
      };
    }
