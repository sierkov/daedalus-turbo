import React, {useState, useEffect} from "react";
import { styled } from '@mui/material/styles';
import Button from '@mui/material/Button';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormControl from '@mui/material/FormControl';
import Radio from '@mui/material/Radio';
import RadioGroup from '@mui/material/RadioGroup';
import Tooltip, { tooltipClasses } from '@mui/material/Tooltip';
import './Settings.scss';

function canonNetworkSource(src)
{
    if (src && (src === "turbo" || src === "p2p"))
        return src;
    return "turbo";
}

function canonValidationMode(mode)
{
    if (mode && (mode === "turbo" || mode === "full"))
        return mode;
    return "turbo";
}

const NoMaxWidthTooltip = styled(({ className, ...props }) => (
    <Tooltip {...props} classes={{ popper: className }} />
))({
    [`& .${tooltipClasses.tooltip}`]: {
        maxWidth: 'none',
    },
});

export default function SyncSettings({ status, confirmReady, trackStatus }) {
    const [networkSource, setNetworkSource] = useState(canonNetworkSource(status?.syncType));
    const [validationMode, setValidationMode] = useState(canonValidationMode(status?.validationMode));
    const [active, setActive] = useState(true);
    useEffect(() => {
    }, [networkSource, validationMode]);
    const doSync = async () => {
        setActive(false);
        await appAPI.configSync(networkSource, validationMode);
        await appAPI.sync(Date.now());
        trackStatus();
    };
    let exploreBtn = <NoMaxWidthTooltip title="Exploration will be enabled after the first successful synchronization." arrow>
        <span>
            <Button className="button" variant="outlined" color="primary" size="large" disabled={true}>
                Explore
            </Button>
        </span>
    </NoMaxWidthTooltip>;
    let primaryAction = 'sync';
    if (status?.syncType !== 'none' && status?.lastBlock && !status?.syncError)
        primaryAction = 'explore';
    const btnStyle = (expState, actState) => {
        return actState === expState ? 'contained' : 'outlined';
    };
    if (status?.lastBlock) {
        exploreBtn = <Button className="button" variant={btnStyle('explore', primaryAction)} color="primary" size="large"
                disabled={!active} onClick={() => confirmReady()}>
            Explore
        </Button>;
    }
    return <div className="sync-settings">
        <div className="row settings">
            <div className="col">
                <div className="option">
                    <h4>Network source</h4>
                    <FormControl className="radio">
                        <RadioGroup aria-labelledby="demo-radio-buttons-group-label" value={networkSource}
                                    name="radio-buttons-group"
                                    onChange={(e, v) => setNetworkSource(v)}>
                            <FormControlLabel value="turbo" control={<Radio/>} label="Turbo Nodes"/>
                            <p className="note-text">data compression enabled</p>
                            <FormControlLabel value="p2p" control={<Radio/>} label="Cardano Network"/>
                            <p className="note-text">data compression not available</p>
                        </RadioGroup>
                    </FormControl>
                </div>
            </div>
            <div className="col">
                <div className="option">
                    <h4>Validation method</h4>
                    <FormControl className="radio">
                        <RadioGroup aria-labelledby="witness-mode-choice" value={validationMode} name="radio-buttons-group"
                                    onChange={(e, v) => setValidationMode(v)}>
                            <FormControlLabel value="turbo" control={<Radio/>} label="Turbo"/>
                            <p className="note-text">consensus and recent transactions</p>
                            <FormControlLabel value="full" control={<Radio/>} label="Full"/>
                            <p className="note-text">consensus and all transactions</p>
                        </RadioGroup>
                    </FormControl>
                </div>
            </div>
        </div>
        <div className="row actions">
            <div className="col">
                {exploreBtn}
            </div>
            <div className="col">
                <Button className="button" variant={btnStyle('sync', primaryAction)} color="primary" size="large"
                        disabled={!active} onClick={doSync}>Sync</Button>
            </div>
        </div>
    </div>;
}