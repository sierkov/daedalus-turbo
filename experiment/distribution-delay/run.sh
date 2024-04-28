for i in `seq 1 3`; do
    bash -c "node measure.js turbo$i.daedalusturbo.org | tee turbo$i.log" &
done
wait