# Contents
- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Test it yourself](#test-it-yourself)
- [Spread the word](#spread-the-word)
- [Quality](#quality)
- [Roadmap](#roadmap)
- [Benchmarks](#benchmarks)

# About
Daedalus Turbo is an open-source project that aims to improve drastically (>=10x) the blockchain synchronization performance of the Daedalus wallet, the primary fully decentralized wallet of the Cardano blockchain. The project has a two-year schedule presented in its [roadmap](#roadmap), and its technical approach is based on two key ideas: reducing the necessary network bandwidth through the use of compression and maximizing the use of parallel computation during the processing of blockchain data. These ideas are further explained in the following research reports:
1. [Highly Parallel Reconstruction of Wallet History in the Cardano Blockchain](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf);
2. [Scalability of Bulk Synchronization in the Cardano Blockchain](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf).

The code currently validates the blockchain data only for general consistency: that the chain of block hashes is continuous and that the slot numbers are monotonically increasing. However, the parallel Ouroboros-Praos-like validation (as explained in section 4.6 of the [second research report](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf)) is in active development and will be published in this repository once ready. Also, there are plans to add support for [Mithril](https://mithril.network/doc/) in the future.

# Features
Currently supported:
- Incremental synchronization and indexing of compressed blockchain data over the network.
- Incremental synchronization and indexing from a local Cardano Node instance.
- Reconstruction of balances and transaction histories of stake addresses.
- Reconstruction of balances and transaction histories of payment addresses.
- Quick search for transaction data.
- ADA and non-ADA assets.
- Direct reconstruction from compressed blockchain data.

In active development:
- Parallelized Ouroboros-Praos validation of blockchain data.
- Computation of staking rewards.
- Desktop Cardano Explorer app.

Currently not supported:
- Validation of Plutus and other scripts.

As the project matures and moves through its [roadmap](#roadmap), the list of supported features will grow.

# Requirements
- 8+-core CPU.
- 8+GB of RAM. The precise amount depends on the number of simultaneous execution threads your CPU can handle. The higher the number, the more RAM is needed.
- a fast SSD with ~60GB of free space:
  - ~50GB for the compressed blockchain data and search indices.
  - ~10GB for temporary use during indexing.

# Test it yourself

### Prerequisites
To run this test you need the following software packages installed:
- [Git](https://git-scm.com/) to get a copy of this repository.
- [Docker](https://www.docker.com/products/docker-desktop/) to launch the software in an isolated environment.

### Commands

Clone this repository and make it your working directory:
```
git clone https://github.com/sierkov/daedalus-turbo.git dt
cd dt
```

Build and start a Docker container:
```
docker build -t dt -f Dockerfile.test .
docker run -it dt
```

Download the Cardano blockchain from a demo compressing server, [turbo1.daedalusturbo.org](http://turbo1.daedalusturbo.org/) and construct search indices:
- This command works incrementally, so on successive runs it will reprocess only new and updated chunks.
- The resulting data is stored in /data/cardano directory inside the container.
- The command should take between 20 and 60 minutes to synchronize the whole Cardano blockchain from scratch. The precise time will depend on the speed of your Internet connection, the number of CPU cores, and the current load on the demo server.
- If you encounter network errors during the execution of the sync-http command, please check if the demo compressing server is currently available by opening its address in your web browser.
Do not hesitate to open a GitHub issue if networking issues persist for 24 hours.
```
./dt sync-http /data/cardano
```

Reconstruct the latest balance and transaction history of a stake key:
```
./dt stake-history /data/cardano stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg
```

Reconstruct the latest balance and transaction history of a payment key:
```
./dt pay-history /data/cardano addr1q86j2ywajjgswgg6a6j6rvf0kzhhrqlma7ucx0f2w0v7stuau7usgm94re2n6fhe9ee88c2u5ta5znnwwtlxpsulzrdqv6rmuj
```

Show information about a transaction:
```
./dt tx-info /data/cardano 357D47E9916B7FE949265F23120AEED873B35B97FB76B9410C323DDAB5B96D1A
```

# Spread the word
Many in the Cardano community, including some developers of Daedalus, don't believe that it's possible to make it noticeably faster. This leads to a situation in which the development is not focused on its performance. If you're persuaded by the evidence presented here, share it on social media with those around you. Changing the beliefs of people can be harder than building top-notch technology. So, every single tweet and Facebook post makes a difference. Thank you!

# Quality
The indexing and history-reconstruction code has been tested using a sample of ten thousand randomly-selected stake keys. For 100% of those, the reconstructed ADA balance (excluding rewards) precisely matched the stake recorded in the ledger snapshot produced by Cardano Node. The testing was performed with slot number 106012751 at the tip of the blockchain. The code of the test is located in the [test](test/) directory of this repository.

# Roadmap
The development of the project is organized into the following milestones:
| Milestone | ETA | Status |
| --------- | --- | ------ |
| M1: Show that transaction history can be reconstructed 10x quicker | February 2023 | Ready, review passed |
| M2: Analyze the scalability of the Cardano network protocol and prepare requirements for the accelerated one | June 2023 | Ready, in review |
| M3: Full POC of Daedalus Turbo: fast blockchain data delivery and transaction-history reconstruction | March 2024 | In Progress |
| M4: Integrate the POC into the official Daedalus builds | February 2025 | Planned |

Due to the experimental nature of the project, the ETAs are tentative.
The development can go both faster and slower than expected.

# Benchmarks
The [experiment](./experiment/) directory contains the source code of benchmarks and experiments discussed in the research reports.
