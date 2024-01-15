import React from 'react';
import Button from '@mui/material/Button';
import Asset from './Asset.jsx';
import './AssetList.scss';

export default function AssetList({ assets, count, offset, limit, changeOffset }) {
    const items = Object.entries(assets).map(kv => <Asset key={kv[0]} id={kv[0]} amount={kv[1]} />);
    return <div className="asset-list">
        <h3>Assets: {offset + 1} ... {offset + Object.keys(assets).length}</h3>
        <div className="asset">
            <div className="amount header">Amount</div>
            <div className="id header">Asset Id</div>
        </div>
        {items}
        <Button sx={{ marginRight: '8px' }} variant="contained" color="primary" onClick={() => changeOffset(Math.max(offset - limit, 0))} disabled={offset === 0}>Previous {limit}</Button>
        <Button variant="contained" color="primary" onClick={() => changeOffset(offset + limit)} disabled={offset + limit >= count}>Next {limit}</Button>
    </div>;
}