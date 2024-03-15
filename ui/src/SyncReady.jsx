import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from "@mui/material/Button";
import './Progress.scss';
import './SyncReady.scss';

function LinearProgressWithLabel(props) {
    return (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Box sx={{ width: '100%', mr: 1 }}>
                <LinearProgress variant="determinate" {...props} />
            </Box>
            <Box sx={{ minWidth: 35 }}>
                <Typography variant="body2" color="text.secondary">{`${parseFloat(props.value).toFixed(3)}%`}</Typography>
            </Box>
        </Box>
    );
}

LinearProgressWithLabel.propTypes = {
    value: PropTypes.number.isRequired,
};

export default function SyncReady({ hardware, duration, dataSize, ready, confirmReady }) {
    const hardwareInfo = <div className="hw-info">
        <div className="resource">
            <div className="name">Internet</div>
            <div className="value">{hardware?.internet ?? "unknown"}</div>
        </div>
        <div className="resource">
            <div className="name">CPU</div>
            <div className="value">{hardware?.threads ?? "unknown"}</div>
        </div>
        <div className="resource">
            <div className="name">RAM</div>
            <div className="value">{hardware?.memory ?? "unknown"}</div>
        </div>
        <div className="resource">
            <div className="name">Storage</div>
            <div className="value">{hardware?.storage ?? "unknown"}</div>
        </div>
    </div>;
    return <div className="sync">
        <div>
            <img className="logo-large" src="static/logo.svg"/>
        </div>
        <h1>Synchronization complete</h1>
        <div className="achievement">
            <h2 className="eta">Processed {dataSize} MB of data in {duration} min</h2>
        </div>
        <div>
            <Button className="continue-button"
                    variant="contained" color="primary" size="large" onClick={confirmReady}>Explore</Button>
        </div>
        {hardwareInfo}
    </div>;
}