import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import './Progress.scss';

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

export default function Progress({ progress, names }) {
    const myProgress = Object.fromEntries(names.map(name => [name, progress[name] ?? "0.000%"]));
    const numItems = Object.keys(myProgress).length;
    let progressDetails = <></>;
    let totalProgress = 100;
    const progressItems = Object.entries(myProgress).map((entry, idx) =>
        <div className="progress-item">
            <div>{entry[0]}</div>
            <div>
                <LinearProgressWithLabel color="primary" variant="determinate" value={entry[1].slice(0, -1)} />
            </div>
        </div>
    );
    progressDetails = <>
        {progressItems}
    </>;
    totalProgress = numItems > 0 ? Object.entries(myProgress).map(e => e[1]).reduce((sum, val) => sum + parseFloat(val?.slice(0, -1)), 0) / numItems : 100;
    return <div className="progress">
        <div className="progressItem total">
            <div>total</div>
            <div>
                <LinearProgressWithLabel color="primary" variant="determinate" value={totalProgress} />
            </div>
        </div>
        {progressDetails}
    </div>;
}