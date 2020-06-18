# SocketInjectingFuzzer

## Installation

### Prepare
```
$ git clone https://github.com/mmmds/sif
$ cd sif

$ git clone --depth 1 https://gitlab.com/akihe/radamsa
$ cd radamsa/
$ CFLAGS="-fPIC" make lib/libradamsa.so
```

### Compile
```
$ gcc -I`pwd`/radamsa/c -fPIC -shared -o fuzzer.o fuzzer.c radamsa/lib/libradamsa.so -ldl
```

### Use
```
LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libasan.so.4 /home/mmm/socketfuzzer/fuzzer.o" ./<app>
```
