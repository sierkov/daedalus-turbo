import React from 'react';
import { useParams } from 'react-router-dom';
import TransactionList from './TransactionList.jsx';

export default function Pay() {
    const config = {
        title: 'Payment address',
        type: 'payment key',
        infoMethod: 'payInfo',
        txsMethod: 'payTxs',
        assetsMethod: 'payAssets'
    };
    const params = useParams();
    const hash = params.hash;
    return <TransactionList hash={hash} config={config} />;
}