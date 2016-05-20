NTIMES=5

mkdir -p logs

for M in 10 50 200
do
    for NLAYERS in 1000 10000 100000
    do
        echo $M $NLAYERS
        LD_LIBRARY_PATH='relic/lib' ./src/abke --ca -m $M -t $NTIMES 2>/dev/null &
        LD_LIBRARY_PATH='relic/lib' ./src/abke --server -m $M -q $NLAYERS -t $NTIMES 2>logs/server.$M.$NLAYERS.log &
        sleep 1
        LD_LIBRARY_PATH='relic/lib' ./src/abke --client -m $M -q $NLAYERS -t $NTIMES 2>logs/client.$M.$NLAYERS.log
        sleep 1
    done
done
