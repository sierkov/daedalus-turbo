import React from 'react';
import { useParams } from 'react-router-dom';
import TransactionList from './TransactionList.jsx';

export default function Stake() {
    const config = {
        title: 'Stake address',
        type: 'stake key',
        infoMethod: 'stakeInfo',
        txsMethod: 'stakeTxs',
        assetsMethod: 'stakeAssets'
    };
    const params = useParams();
    const hash = params.hash;
    return <TransactionList hash={hash} config={config} />;
}