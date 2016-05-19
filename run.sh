NTIMES=1

mkdir -p logs

for M in 10 50 200
do

    for NLAYERS in 1000 10000 100000
    do
        echo $M $NLAYERS
        ./src/abke --ca -m $M -t $NTIMES 2>/dev/null &
        ./src/abke --server -m $M -q $NLAYERS -t $NTIMES 2>logs/server.$M.$NLAYERS.log &
        ./src/abke --client -m $M -q $NLAYERS -t $NTIMES 2>logs/client.$M.$NLAYERS.log
    done
done
