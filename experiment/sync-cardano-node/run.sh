#! /bin/env bash
test -d log || mkdir log
for iter in `seq 1 3`; do
    echo "Iteration $iter"
    test -d /data/cardano-node && rm -rf /data/cardano-node/*
    sync; echo 3 > /proc/sys/vm/drop_caches
    echo "kernel caches flushed, starting the benchmark"
    docker-compose up -d
    echo "waiting for 15 seconds to let cardano-node and cardano-wallet to start"
    sleep 15
    echo "starting docker stats collection in background"
    bash -c "while true; do docker stats --no-stream >> log/run-$iter-docker-stats.log; sleep 1; done" &
    echo "starting measure.js"
    node measure.js | tee log/measure-$iter.log
    echo "killing background jobs"
    jobs -p | xargs -r kill
    docker-compose down
done