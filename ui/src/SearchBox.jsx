import React, { useEffect, useRef, useState } from 'react';
import { bech32 } from 'bech32';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import SearchIcon from '@mui/icons-material/Search';
import './SearchBox.scss';

export default function SearchBox({ noPadding }) {
    const navigate = useNavigate();
    const [searchInput, setSearchInput] = useState('');
    const [searchReady, setSearchReady] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => {
        const isError = searchInput?.length > 0 && !searchReady;
        setError(isError ? 'Neither a 64-character tx hash nor a valid BECH32 address' : '');
    }, [searchInput, searchReady]);
    const validateSearchInput = (ev) => {
        const query = ev?.target?.value?.replace(' ', '');
        let bech32Ok;
        try {
            const info = bech32.decode(query, 128);
            const bytes = bech32.fromWords(info.words);
            console.log('bech32:', info, 'bytes:', bytes);
            if (info?.prefix === 'stake' && bytes?.length == 29) {
                bech32Ok = { prefix: info.prefix, data: bytes };
            } else if (info?.prefix === 'addr' && bytes?.length >= 29) {
                bech32Ok = { prefix: info.prefix, data: bytes };
            }
        } catch (err) {
            console.error('bech32 decoding error:', err);
        }
        const isTx = query?.length === 64;
        const isHex = !!query?.match(/^[A-F0-9]+$/i);
        const isReady = (isHex && isTx) || !!bech32Ok;
        //console.log('searchInput:', query, 'len:', query?.length, 'ready:', isReady, 'isHex:', isHex, 'isTx:', isTx, 'bech32Ok:', !!bech32Ok);
        setSearchInput(query);
        setSearchReady(isReady);
    };
    const doSearch = (ev) => {
        const query = searchInput;
        console.log('doSearch:', query);
        setSearchInput('');
        setSearchReady(false);
        if (query.length === 64) navigate('/tx/' + query);
        else navigate('/bech32/' + query);
    };
    const noPaddingClass = noPadding ? "no-padding" : "";
    return <div className={['search-box', noPaddingClass].join(' ')}>
            <TextField className="search-input"
                onChange={validateSearchInput}
                placeholder="Enter the hexadecimal tx hash or a BECH32 address"
                fullWidth
                inputRef={input => input && input.focus()}
                error={!!error}
                label={error}
                variant="outlined" color="primary" />
            <Button className="search-button" startIcon={<SearchIcon />}
                variant="contained" color="primary" size="large" onClick={doSearch} disabled={!searchReady}>Search</Button>
        </div>;
}
