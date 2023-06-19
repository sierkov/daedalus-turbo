# Contents
- [About](#about)
- [Test it yourself](#test-it-yourself)
- [Spread the word](#spread-the-word)
- [Features](#features)
- [Quality](#quality)
- [Requirements](#requirements)
- [Roadmap](#roadmap)
- [Performance notes](#performance-notes)
- [Benchmark reproduction](#benchmark-reproduction)

# About
Daedalus Turbo is an open-source project that aims to drastically (>=10x) improve blockchain synchronization performance of the Daedalus wallet, the primary fully-decentralized wallet of the Cardano blockchain. The project has a two-year schedule presented in its [roadmap](#roadmap),
and its technical approach is explained in the following research reports:
1. [Highly Parallel Reconstruction of Wallet History in the Cardano Blockchain](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf);
2. [Scalability of Bulk Synchronization in the Cardano Blockchain](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf).

This repository currently contains an implementation of the highly-parallel wallet-history-reconstruction method presented in the [first research report](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf).
On a modern computer, it can often process the whole blockchain and reconstruct a wallet's history in a minute or quicker.
In comparison, Daedalus takes several hours when one adds a new wallet,
even when the blockchain data is already fully synced. As the project moves forward, other components will be added.

The code currently assumes blockchain data to be pre-validated. However, in the future, the project plans to support two validation methods:
- Parallel Ouroboros-Praos-like validation, as explained in section 4.6 of the [second research report](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf);
- [Mithril](https://mithril.network/doc/).

# Test it yourself
Check that you are ready for the test:
- You have [Git](https://git-scm.com/) installed to get a copy of this repository.
- You have [Docker](https://www.docker.com/products/docker-desktop/) installed to launch the software in an isolated environment.
- You have [Daedalus](https://daedaluswallet.io/en/download/) installed and recently synced to get a local copy of the blockchain data. Specifically, a path to the directory with *.chunk files will be needed. Normally, one can find these files under the following locations:
  - On Windows: %APPDATA%\Daedalus Mainnet\chain\immutable 
  - On Linux: ~/.local/share/Daedalus/mainnet/chain/immutable
  - On Mac: ~/Library/Application Support/Daedalus/mainnet/chain/immutable
- You know a stake address (in BECH32 "stake1XXXXX" format) for which you can verify the list of associated transactions using Daedalus or a blockchain explorer. The stake address can be of any wallet not just the ones registered with your installation of Daedalus.
- You have an open console window to run the commands described below.

Clone this repository and make it your working directory:
```
git clone https://github.com/sierkov/daedalus-turbo.git dt
cd dt
```

Run the following commands to prepare and start a container, replacing:
- */your-immutable* with the path to the *.chunk files with the blockchain data.
- */your-indices* with the location where you'd like the newly built indices to be stored. If in doubt, simply use the path to your current directory.
```
docker build -t dt -f Dockerfile.test .
docker run -it --rm -v /your-immutable:/data/immutable -v /your-indices:/data/indices dt
```

Within the container's shell run the following commands to create the indices
and perform the transaction-history reconstruction for a given stake key.
The string *stake1XXXXXX* must be replaced with the stake key of your choosing.
```
sudo chown -R dev:dev /data/indices
./create-index /data/immutable /data/indices
./search-index /data/immutable /data/indices stake1XXXXXX
```
The third command will output to the console the list of transactions related to the specified stake key along with their metadata.

N.B.: If the transactions do not match your alternative source, please double check that the copy of the blockchain data that you've passed to the command is up to date!

# Spread the word
Many in the Cardano community, including some developers of Daedalus, don't believe that it's possible to make it noticeably faster. This leads to a situation in which the development is not focused on the performance. If you're persuaded by the evidence presented here, share it on social media with those around you. Changing the beliefs of people can be harder than building top-notch technology. So, every single tweet and Facebook post makes a difference. Thank you!

# Features
The current version of the method is optimized for personal wallets (wallets with less than one thousand transactions) and supports only a minimal set of Cardano features:
- ADA-only transactions.
- Shelley-era addresses with an explicit stake-key hash.
- Withdrawals-only for staking rewards; inflows are ignored.

As the project matures and moves through its [roadmap](#roadmap), the list of supported features will grow.

# Quality
The code has been tested using a sample of ten thousand randomly-selected stake keys. For 100% of those the reconstructed ADA balance (excluding rewards)
precisely matched the stake recorded in the ledger snapshot produced by Cardano Node. The testing was performed with the slot number 77374448 at the tip of the blockchain. The code of the test is located in [test](test/) directory of this repository.

# Requirements
- 20GB of free disk space: 10GB for the created indices and another 10GB for temporary files, which will be deleted once the indices are created.
- 4GB+ of RAM. The precise amount depends on the number of threads that your CPU can handle. 4GB shall be sufficient for up to 20 threads. For 48 threads about 8GB will be needed.
- A local copy of ImmutableDB generated by Cardano Node.
- A Docker installation. Ensure that all host's CPUs are available within the container for best performance.

# Roadmap
The development of the project is organized into the following milestones:
| Milestone | ETA | Status |
| --------- | --- | ------ |
| M1: Show that transaction history can be reconstructed 10x quicker | February 2023 | Ready, review passed |
| M2: Analyze the scalability of the Cardano network protocol and prepare requirements for the accelerated one | June 2023 | Ready, in review |
| M3: Full POC of Daedalus Turbo: fast blockchain data delivery and transaction-history reconstruction | March 2024 | Planned |
| M4: Integrate the POC into the official Daedalus builds | February 2025 | Planned |

Due to the experimental nature of the project, the ETAs are tentative.
The development can go both faster and slower than expected.

# Performance notes
- The performance of the method depends on the number of CPU cores you have.
  To fully benefit from the acceleration, benchmarking with 16+ cores is recommended.
- The performance of the method depends on the speed of your local storage.
  The more cores you have, the higher it should be. The necessary storage
throughput should increase by about 250 megabytes/sec for every additional CPU thread.
  So, if you plan to run 20 threads, ensure your SSD can reach 5000 megabytes/sec in the sequential read performance.
- The use of docker volumes can lead to lower performance on some platforms, such as Windows.
  So, when benchmarking to reproduce the paper's results,
  please use exactly the same setup as presented in the paper:
  Ubuntu Linux 22.04 LTS as your host OS.

# Experiment reproduction
The [experiment](./experiment/) directory contains source code of benchmarks and experiments discussed in the project's research reports.

## Hardware and reproducibility

To ensure that all experiments are reproducible, they were performed
on bare-metal servers rented at [Vultr](https://www.vultr.com/products/bare-metal). Bare-metal servers reduce the possibility of alternative workloads
affecting experiment results.

Specifically, a server with a 24-core AMD EPYC 7443P CPU is used.
This variant was chosen to better highlight the benefits of parallel processing.
At the same time, since the primary users of Daedalus wallets are consumers, 
where applicable the experiments were additionally run with
a reduced thread count of eight to simulate consumer-grade laptops.

## Highly-parallel wallet-history reconstruction in Cardano blockchain

Start a new bare-metal server with an AMD EPYC 7443P CPU running under Ubuntu 22.04 LTS. Servers with exactly the same configuration as in the paper can be rented at [Vultr](https://www.vultr.com/products/bare-metal).

create a raid0 disk array and mount it under /data:
```
mdadm --create --verbose /dev/md1 --level=0 --raid-devices=2 /dev/nvme0n1 /dev/nvme1n1
mkfs -t ext4 /dev/md1
mkdir /data
mount /dev/md1 /data
```

install the necessary packages:
```
apt install -y docker-compose
cd /root
git clone https://github.com/scottchiefbaker/dool
cd dool
python3 install.py
/bin/bash <(curl -sL https://deb.nodesource.com/setup_18.x)
apt install -y nodejs
```

copy raw blockchain data from a cardano-node instance:
```
mkdir /data/cardano-node
cp -r /your-cardano-node/immutable /data/cardano-node
```
Note: the benchmarks in the paper were made when the tip of the Cardano blockchain was at the slot number 77374448.

Optional: copy the ledger state from a cardano-node instance - needed only if you plan to benchmark against cardano-wallet:
```
cp -r /your-cardano-node/ledger /data/cardano-node
```

Optional: copy pooldb from a cardano-wallet instance - needed only if you plan to benchmark against cardano-wallet:
```
mkdir /data/cardano-wallet
cp /your-cardano-wallet/stake-pools.sqlite /data/cardano-wallet
```

clone this repository and build the docker image:
```
git clone https://github.com/sierkov/daedalus-turbo dt
cd dt
docker build -t dt -f Dockerfile.test .
```
N.B.: The latest version of the code should work perfectly well, but in the case you'd like to precisely reproduce the paper's results, use the version of the code tagged "preview-20230104" and the corresponding version of the README for the instructions since some names of binaries have changed since then.

create lz4 compressed copies of all immutabledb chunks:
```
docker run --rm -v /data/cardano-node/immutable:/immutable dt bash -c "sudo chown -R dev:dev /immutable; ./lz4 compress /immutable"
```

run the benchmarks:
```
cd experiments/bench-algo
bash run-bench.sh
```
Expect the bench-algo benchmark to take about three hours when using exactly
the same hardware config.
All experiment data will be saved into log directory next to the run-bench.sh script.

Optionally, run the benchmarks of Cardano Wallet:
```
cd experiments/bench-cardano-wallet
echo "the word list to add a test wallet to cardano wallet" > .secret
bash run-bench.sh
```
Expect the bench-cardano-wallet benchmark to take about ten hours when using exactly
the same hardware config.
All experiment data will be saved into log directory next to the run-bench.sh script.
