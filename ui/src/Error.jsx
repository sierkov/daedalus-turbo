import React from 'react';
import Button from '@mui/material/Button';
import './Error.scss';

export default function Error({ issues, onContinue }) {
    const doExit = () => {
        appAPI.exit();
    };
    const issueList = issues.map(i => <p className="message">{i.description}</p>);
    let continueBtn;
    if (onContinue)
        continueBtn = <Button sx={{ marginLeft: '8px' }} className="exit-button"
                variant="outlined" color="secondary" size="large" onClick={onContinue}>Continue</Button>;
    return <div className="error">
        <div className="error-box">
            <h3>Error</h3>
            {issueList}
            <div className="buttons">
                <Button className="exit-button"
                    variant="contained" color="primary" size="large" onClick={doExit}>Exit</Button>
                {continueBtn}
            </div>
        </div>
    </div>;
}