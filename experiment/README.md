# Experiments

## From "Highly-parallel wallet-history reconstruction in Cardano blockchain" paper

- [bench-algo](./bench-algo/) - the code to measure the performance of the highly-parallel wallet-history-reconstruction method.
- [bench-cardano-wallet](./bench-cardano-wallet/) - the code to measure the performance of wallet-history reconstruction by Cardano wallet.

## From "Networking scalability of Cardano blockchain" paper

- networking-cost simulation
- max number of simultaneous turbo wallets
- stake-pool incentives calculations
- [cardano-topology](./cardano-topology/) - the code to collect all IP addresses with which a Cardano node instance establishes TCP connections during the synchronization process.
- cardano-blockfetch (haskell+rust) - measure the peak bandwidth of Cardano Node?
- cardano-chainsync (haskell+rust) - measure the peak bandwidth of Cardano Node?
- [bittorrent-watcher](./bittorrent-watcher/) - the code measuring performance of data-delivery using BitTorrent v2 protocol as implemented in [libtorrent](https://libtorrent.org/).
- [mithril-compression](./mithril-snapshot/) - the code comparing the compression ratio and compression/decompression speed of per-chunk [Zstandard](https://github.com/facebook/zstd) compression versus tar+gzip as used by Mithril in April of 2023.

## Replicating the hardware environment used in performance-focused experiments
To ensure that all experiments are reproducible, they were performed
on bare-metal servers rented at [Vultr](https://www.vultr.com/products/bare-metal).
Bare-metal servers reduce the possibility of alternative workloads affecting experiment results.
Specifically, a server with a 24-core AMD EPYC 7443P CPU was used.
This variant was chosen to better highlight the benefits of parallel processing.
At the same time, since the primary users of Daedalus wallets are consumers, 
where applicable, the experiments were additionally run with
a reduced thread count of eight to simulate consumer-grade laptops.

### Setup

Start a new bare-metal server with an AMD EPYC 7443P CPU running under Ubuntu 22.04 LTS. Servers with exactly the same configuration as in the paper can be rented at [Vultr](https://www.vultr.com/products/bare-metal).

Create a raid0 disk array and mount it under /data:
```
mdadm --create --verbose /dev/md1 --level=0 --raid-devices=2 /dev/nvme0n1 /dev/nvme1n1
mkfs -t ext4 /dev/md1
mkdir /data
mount /dev/md1 /data
```

Install the necessary packages:
```
apt install -y docker-compose
cd /root
git clone https://github.com/scottchiefbaker/dool
cd dool
python3 install.py
/bin/bash <(curl -sL https://deb.nodesource.com/setup_18.x)
apt install -y nodejs
```

Copy raw blockchain data from a Cardano Node instance:
```
mkdir /data/cardano-node
cp -r /your-cardano-node/immutable /data/cardano-node
```
Note: the benchmarks in the paper were made when the tip of the Cardano blockchain was at slot number 77374448.

Optional: copy the ledger state from a Cardano Node instance - needed only if you plan to benchmark against Cardano Wallet:
```
cp -r /your-cardano-node/ledger /data/cardano-node
```

Optional: copy pooldb from a Cardano Wallet instance - needed only if you plan to benchmark against Cardano Wallet:
```
mkdir /data/cardano-wallet
cp /your-cardano-wallet/stake-pools.sqlite /data/cardano-wallet
```

Clone this repository and build the docker image:
```
git clone https://github.com/sierkov/daedalus-turbo dt
cd dt
git checkout release-20230201
docker build -t dt -f Dockerfile.test .
```
N.B.: The latest version of the code should work perfectly well, but in case you'd like to precisely reproduce the paper's results, use the version of the code tagged "preview-20230104" and the corresponding version of the README for the instructions since some names of binaries have changed since then.

Create lz4 compressed copies of all ImmutableDB chunks:
```
docker run --rm -v /data/cardano-node/immutable:/immutable dt bash -c "sudo chown -R dev:dev /immutable; ./lz4 compress /immutable"
```

### Running the experiments
Run the benchmarks:
```
cd experiments/bench-algo
bash run-bench.sh
```
Expect the bench-algo benchmark to take about three hours when using exactly
the same hardware config.
All experiment data will be saved into the log directory next to the run-bench.sh script.

Optionally, run the benchmarks of Cardano Wallet:
```
cd experiments/bench-cardano-wallet
echo "the word list to add a test wallet to cardano wallet" > .secret
bash run-bench.sh
```
Expect the bench-cardano-wallet benchmark to take about ten hours when using precisely
the same hardware config.
All experiment data will be saved into log directory next to the run-bench.sh script.
