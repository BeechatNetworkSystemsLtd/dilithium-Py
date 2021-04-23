# PY-PQC

This repository contains the reference implementation of the [Dilithium](https://github.com/pq-crystals/dilithium) Post Quantum Cryptography algorithms usable through Python Native Interface wrappers.

## Build

For make a Python wrapper you should use cmake:
```sh
mkdir build
cd build
cmake ..
make
```
The build result will be available in the `/build` directory.
Or you can just open the project in Visual Studio and build it inside the IDE.

## Usage

To use the Kyber functions in a PYTHON project, you must use shared libraries located in the `/build` directory.
Insert Python module into your application and use necessary functions. Shared libraries should located in the same directory. For example:

```python
import ctypes
import pydilithium;
...
a = ''
b = ''
c = POINTER(a);
d = POINTER(b);

pykyber.pqcrystals_dilithium2_ref_keypair(c, d)
print(a)
print(b)
}
```

The necessary shared libraries are placed in `/build` directory. It is not necessary to use all classes (with `_aes` and without). Just choose what you want to use.





