Attribute-based Key Exchange Implementation
===========================================

To compile:

```
mkdir -p build/autoconf
autoreconf -i
bash relic.sh
./configure
make
```


To reproduce the experiments:

Run `tc.sh`
Run `./run.sh | tee results.txt`
Run `python graph.py results.txt`
