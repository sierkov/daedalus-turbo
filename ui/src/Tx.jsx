import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import stringify from 'json-stable-stringify';
import Address from './Address.jsx';
import Asset from './Asset.jsx';
import Prop from './Prop.jsx';
import NavBar from './NavBar.jsx';
import Transition from './Transition.jsx';
import './Tx.scss';

function TxInput(info) {
    return <div className="tx-input">
        <div className="tx-indexed">
            <div className="tx-index">#{info.idx}</div>
            <Prop name="Tx Hash/Out">
                <a href={'#/tx/' + info?.hash}>{info?.hash}</a>&nbsp;&nbsp;#{info?.outIdx}
            </Prop>
        </div>
    </div>;
}

function TxInputs({ items }) {
    const domItems = items?.map((i, idx) =>
        <TxInput key={i.hash + '/' + i.outIdx} idx={idx} {...i} />
    );
    return <div className="tx-inputs">
        <h3>Inputs: {items?.length ?? 0}</h3>
        {domItems}
    </div>;
}

function TxOutput(info) {
    const addr = <Address {...info?.address} />;
    const assetList = info?.assets ? Object.entries(info.assets).map(([k, v]) => <Asset key={k} id={k} amount={v} />): undefined;
    const assets = assetList ? <Prop name="Assets"><div className="assets">{assetList}</div></Prop> : undefined;
    return <div className="tx-output">
        <div className="tx-indexed">
            <div className="tx-index">#{info.idx}</div>
            <div className="amount">{info?.amount}</div>
            <div className="address">{addr}</div>
        </div>
    </div>;
}

function TxOutputs({ items }) {
    const domItems = items?.map((i, idx) =>
        <TxOutput key={stringify(i.address) + '/' + i.amount} idx={idx} {...i} />
    );
    return <div className="tx-outputs">
        <h3>Outputs: {items?.length ?? 0}</h3>
        {domItems}
    </div>;
}

export default function Tx({ hash }) {
    const params = useParams();
    if (!hash) hash = params.hash;
    const [txInfo, setTxInfo] = useState({});
    let infoHash;
    useEffect(() => {
        if (infoHash !== hash) {
            if (Object.keys(txInfo).length > 0)
                setTxInfo({});
            infoHash = hash;
            appAPI.txInfo(hash).then((r) => {
                setTxInfo(r);
            });
        }
    }, [hash]);
    if (Object.keys(txInfo).length === 0)
        return <Transition />;
    if (txInfo?.error?.length > 0)
        return <div className="content">
            <NavBar />
            <div className="tx">
                <div className="tx-header">
                    <h3>Error</h3>
                    <p>Couldn't retrieve data for transaction {hash}: {txInfo.error}</p>
                </div>
            </div>
        </div>;
    return <div className="content">
        <NavBar />
        <div className="tx">
            <div className="tx-header">
                <h3>Transaction</h3>
                <Prop name="Hash" value={txInfo?.hash} />
                <Prop name="Time">
                    <div className="flex">
                        <Prop name="Timestamp" value={txInfo?.slot?.timestamp} />
                        <Prop name="Epoch" value={txInfo?.slot?.epoch} />
                        <Prop name="Slot" value={txInfo?.slot?.slot} />
                    </div>
                </Prop>
                <Prop name="Location">
                    <div className="flex">
                        <Prop name="Offset" value={txInfo?.offset} />
                        <Prop name="Size" value={txInfo?.size + ' bytes'} />
                        </div>
                </Prop>
            </div>
            <TxInputs items={txInfo?.inputs} />
            <TxOutputs items={txInfo?.outputs} />
        </div>
    </div>;
}