import React, {useEffect, useState} from 'react';
import {useNavigate, useParams} from "react-router-dom";
import Button from "@mui/material/Button";
import Error from './Error.jsx';
import Transition from "./Transition.jsx";
import './Export.scss';

export default function Export() {
    const [ready, setReady] = useState(false);
    const [error, setError] = useState(false);
    const params = useParams();
    const navigate = useNavigate();
    const path = params.path;
    let exportPath;
    useEffect(() => {
        if (exportPath !== path) {
            exportPath = path;
            setReady(false);
            console.log('export started');
            appAPI.export(path).then((res) => {
                console.log('export finished OK:', res);
                if (res?.error)
                    setError(res.error);
                else
                    setReady(true);
            }).catch((e) => {
                console.log('export finished with an error:', e);
                setError(e);
            })
        }
        return () => {};
    }, [exportPath]);
    const doHome = (ev) => {
        navigate('/');
    };
    if (error)
        return <Error issues={[ { 'description': error } ]} onContinue={doHome} />
    if (!ready)
        return <Transition progressWeights={ { 'chunk-export': 0.9, 'ledger-export': 0.01 } } />;
    return <div className="export">
        <div>
            <img className="logo-large" src="static/logo.svg"/>
        </div>
        <h1>Daedalus export complete</h1>
        <Button className="continue-button"
                variant="contained" color="primary" size="large" onClick={doHome}>OK</Button>
    </div>;
}