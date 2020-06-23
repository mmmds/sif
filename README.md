# SocketInjectingFuzzer

## Installation

### Prepare
```
$ git clone https://github.com/mmmds/sif
$ cd sif

$ git clone --depth 1 https://gitlab.com/akihe/radamsa
$ cd radamsa/
$ CFLAGS="-fPIC" make lib/libradamsa.o
```

### Compile
```
$ gcc -I`pwd`/radamsa/c -fPIC -shared -o fuzzer.o fuzzer.c radamsa/lib/libradamsa.o -ldl
```

### Use
```
LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libasan.so.4 /home/mmm/sif/fuzzer.o" ./<app>
```

### Findings
- Chocolate Doom, Crispy Doom
  - https://github.com/chocolate-doom/chocolate-doom/issues/1292 ([CVE-2020-14983](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14983))
  - https://github.com/chocolate-doom/chocolate-doom/issues/1293
- Teeworlds
  - https://github.com/teeworlds/teeworlds/issues/2642
  - https://github.com/teeworlds/teeworlds/issues/2643
  - https://github.com/teeworlds/teeworlds/issues/2644
  - https://github.com/teeworlds/teeworlds/issues/2645
  - https://github.com/teeworlds/teeworlds/issues/2649
- Zandronum
  - https://zandronum.com/tracker/view.php?id=3828
  - https://zandronum.com/tracker/view.php?id=3829
  - https://zandronum.com/tracker/view.php?id=3830
