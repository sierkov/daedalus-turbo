import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import Prop from './Prop.jsx';
import TxRefList from './TxRefList.jsx';
import NavBar from './NavBar.jsx';
import Transition from './Transition.jsx';

export default function Pay({ hash }) {
    const params = useParams();
    if (!hash) hash = params.hash;
    const [info, setInfo] = useState({});
    let infoHash;
    useEffect(() => {
        if (infoHash !== hash) {
            if (Object.keys(info).length > 0)
                setInfo({});
            infoHash = hash;
            appAPI.payInfo(hash).then((r) => setInfo(r));
        }
    }, [hash]);
    if (Object.keys(info).length === 0)
        return <Transition />;
    if (info?.error?.length > 0)
        return <div className="content">
            <NavBar />
            <div className="payment-key tx">
                <div className="tx-header">
                    <h3>Error</h3>
                    <p>Couldn't retrieve data for payment key {hash}: {info.error}</p>
                </div>
            </div>
        </div>;
    let txRefs;
    if (info?.transactions?.length > 0) {
        txRefs = <TxRefList key={hash} transactions={info?.transactions} />;
    } else {
        txRefs = <>This address has never been referenced in the blockchain.</>;
    }
    return <div className="content">
        <NavBar />
        <div className="page-content">
            <div className="payment-key tx">
                <div className="tx-header">
                    <h2>Payment address</h2>
                    <Prop name="Hash" value={info?.id?.hash} />
                    <Prop name="Balance" value={info?.balance} />
                    <Prop name="Withdrawals" value={info?.withdrawals} />
                    <Prop name="Transactions" value={info?.txCount} />
                </div>
                {txRefs}
            </div>
        </div>
    </div>;
}