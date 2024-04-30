import fetch from 'node-fetch';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const shelleySlotToTime = (slot) =>
{
    const shelleyBeginSlot = 208 * 21600;
    const shelleyBeginTime = 1596059091;
    if (slot < shelleyBeginSlot)
        throw Error(`Got a pre-Shelley slot number: {$slot}!`);
    return (shelleyBeginTime + (slot - shelleyBeginSlot)) * 1000;
};

const getLastSlot = async(host) => {
    const url = `http:/${host}/chain.json`;
    const resp = await fetch(url);
    const chain = await resp.json();
    const fetchTime = Date.now();
    if (!Array.isArray(chain?.epochs))
        throw Error(`${url}: must contain epochs array!`);
    const lastEpoch = chain?.epochs?.pop();
    if (!lastEpoch)
        throw Error(`${url}: epochs array must not be empty!`);
    const lastSlot = lastEpoch?.lastSlot;
    if (!lastSlot)
        throw Error(`${url}: last epoch must contain lastSlot attribute!`);
    return lastSlot;
};

const measure = async(host) => {
    let lastBlockTime = shelleySlotToTime(await getLastSlot(host));
    const requestPeriod = 1000;
    for (let ri = 0; ri < 3600; ++ri) {
        const reqTime = Date.now();
        const lastSlot = await getLastSlot(host);
        const lastSlotTime = shelleySlotToTime(lastSlot);
        const now = Date.now();
        if (lastSlotTime > lastBlockTime) {
            const delay = now - lastSlotTime;
            console.log(host, ri, now, lastSlot, lastSlotTime, delay);
            lastBlockTime = lastSlotTime;
        }
        const reqDuration = now - reqTime;
        if (reqDuration < requestPeriod)
            await sleep(requestPeriod - reqDuration);
    }
};

if (process.argv.length < 3) {
    console.log("Usage: node measure.js <host>");
    process.exit(1);
}
(async() => {
    await measure(process.argv[2]);
})();
