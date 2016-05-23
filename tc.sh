sudo tc qdisc add dev lo root handle 1: tbf rate 200mbit burst 100000 limit 10000
sudo tc qdisc add dev lo parent 1:1 handle 10: netem delay 33msec
