import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from "@mui/material/Button";
import HardwareStatus from '../HardwareStatus.jsx';
import './Ready.scss';

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

export default function SyncReady({ hardware, duration, dataSize, confirmReady }) {
    return <div className="sync">
        <div>
            <img className="logo-large" src="static/logo.svg"/>
        </div>
        <h1>Synchronization complete</h1>
        <div className="achievement">
            <h2 className="eta">Processed {Math.round(dataSize) / 1000} GB of data in {duration} min</h2>
        </div>
        <div>
            <Button className="continue-button"
                    variant="contained" color="primary" size="large" onClick={confirmReady}>Explore</Button>
        </div>
        <HardwareStatus hardware={hardware} summary />
    </div>;
}