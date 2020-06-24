# SocketInjectingFuzzer

SocketInjectingFuzzer is a dumb fuzzer, focused on applications working in a client-server architecture. It uses the `LD_PRELOAD` trick to hook network sending functions (`sendto`, `send`, `write` etc.) and mutates outgoing data using [radamsa](https://gitlab.com/akihe/radamsa).

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

## Usage
```
LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libasan.so.4 /home/mmm/sif/fuzzer.o" ./<app>
```
### Settings
- `verbose` - useful for debugging (default `0`)
- `fuzz` - enable fuzzing (default `1`)
- `dump` - dump received network communication (default `0`)
- `seed` - seed for radamsa (random value if not set)
- `repeat` - mutate and send every packet x more times
- `wait` - wait x seconds before fuzzing starts
- `switch_file` - fuzz only if given file exists
- `target_ip` - fuzz only given target (default `127.0.0.1`)
- `target_port` - fuzz only given port (all ports if not set)
- `chance` - chance 1-100 for fuzzing a packet (default `100`)

Example usage:
```
SIF_OPTIONS="fuzz=1:verbose=1:dump=1:dump_output=../:seed=123:skip=5:repeat=10:wait=3:switch_file=../1.switch:target_ip=127.0.0.1:target_port=80:chance=50" LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libasan.so.4 /home/mmm/sif/fuzzer.o" ./<app>
```

## TODO
- [x] hook `sendto`
- [ ] hook `send`, `write`

## Findings
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
