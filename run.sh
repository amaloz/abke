NTIMES=10
ONLINE=-o

mkdir -p logs

for M in 10 100 1000
do

    for NLAYERS in 1000 10000 100000
    do
        echo $M $NLAYERS
        ./a.out --ca -m $M -t $NTIMES 2>/dev/null &
        ./a.out --server -m $M -q $NLAYERS -t $NTIMES $ONLINE 2>logs/server.$M.$NLAYERS.log &
        ./a.out --client -m $M -q $NLAYERS -t $NTIMES $ONLINE 2>logs/client.$M.$NLAYERS.log
    done
done
