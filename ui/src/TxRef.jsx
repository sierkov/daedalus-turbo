import React from 'react';
import './TxRef.scss';

export default function TxRef(info) {
    let balanceChanges = info?.balanceChange.split('; ').filter(b => b?.length > 0).map(b => <p title={b}>{b}</p>)
    return <div className="tx-ref">
        <div className="timestamp">{info?.slot?.timestamp}</div>
        <div className="txo" title={info?.hash}><a href={'#/tx/' + info?.hash}>{info?.hash}</a></div>
        <div className="balance">{balanceChanges}</div>
    </div>;
}