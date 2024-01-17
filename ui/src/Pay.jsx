import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import Tab from '@mui/material/Tab';
import TabContext from '@mui/lab/TabContext';
import TabList from '@mui/lab/TabList';
import TabPanel from '@mui/lab/TabPanel';
import AssetList from './AssetList.jsx';
import Prop from './Prop.jsx';
import Transition from './Transition.jsx';
import TxRefList from './TxRefList.jsx';
import NavBar from './NavBar.jsx';

export default function Pay() {
    const [info, setInfo] = useState({});
    const [txOffset, setTxOffset] = useState(0);
    const txLimit = 1000;
    const [assetOffset, setAssetOffset] = useState(0);
    const assetLimit = 1000;
    const [tab, setTab] = useState("txs");
    const changeTab = (ev, newTab) => {
        console.log('changeTab', ev, newTab);
        setTab(newTab);
    };
    const params = useParams();
    const hash = params.hash;
    let infoHash;
    useEffect(() => {
        if (infoHash !== hash) {
            infoHash = hash;
            setInfo({});
            appAPI.payInfo(hash).then(newInfo => setInfo(newInfo));
        }
    }, [params]);
    let cachedTxOffset = 0;
    useEffect(() => {
        if (cachedTxOffset != txOffset) {
            cachedTxOffset = txOffset;
            const oldInfo = { ... info };
            setInfo({});
            appAPI.payTxs(hash, txOffset, txLimit).then(newTxs => setInfo({ ...oldInfo, transactions: newTxs?.transactions }));
        }
    }, [txOffset]);
    let cachedAssetOffset = 0;
    useEffect(() => {
        if (cachedAssetOffset != assetOffset) {
            cachedAssetOffset = assetOffset;
            const oldInfo = { ... info };
            setInfo({});
            appAPI.payAssets(hash, assetOffset, assetLimit).then(newAssets => setInfo({ ...oldInfo, assets: newAssets?.assets }));
        }
    }, [assetOffset]);
    if (Object.keys(info).length === 0)
        return <Transition />;
    if (info?.error?.length > 0)
        return <div className="content">
            <NavBar />
            <div className="stake-key tx">
                <div className="tx-header">
                    <h3>Error</h3>
                    <p>Couldn't retrieve data for pay key {hash}: {info.error}</p>
                </div>
            </div>
        </div>;
    let txRefs, assetRefs;
    if (info?.assets && Object.keys(info.assets).length > 0) {
        assetRefs = <AssetList assets={info?.assets} count={info?.assetCount} offset={assetOffset} limit={assetLimit} changeOffset={(newOff) => setAssetOffset(newOff)} />;
    } else {
        assetRefs = <p>This address has no associated non-ADA assets</p>;
    }
    if (info?.transactions?.length > 0) {
        txRefs = <TxRefList transactions={info?.transactions} count={info?.txCount} offset={txOffset} limit={txLimit} changeOffset={(newOff) => setTxOffset(newOff)} />;
    } else {
        txRefs = <>This address has never been referenced in the blockchain.</>;
    }
    return <div className="content">
        <NavBar />
        <div className="page-content">
            <div className="stake-key tx">
                <div className="tx-header">
                    <h2>Payment address</h2>
                    <Prop name="Hash" value={info?.id?.hash} />
                    <Prop name="Type" value={info?.id?.script ? "script" : "key" } />
                    <Prop name="Balance" value={info?.balance} />
                    <Prop name="Transactions" value={info?.txCount} />
                    <Prop name="Non-ADA Assets" value={info?.assetCount} />
                </div>
                <TabContext value={tab}>
                    <TabList onChange={changeTab}>
                        <Tab label="Transactions" value="txs" />
                        <Tab label="Assets" value="assets" />
                    </TabList>
                    <TabPanel value="txs" sx={{ padding: 0, margin: 0 }}>{txRefs}</TabPanel>
                    <TabPanel value="assets" sx={{ padding: 0, margin: 0 }}>{assetRefs}</TabPanel>
                </TabContext>
            </div>
        </div>
    </div>;
}