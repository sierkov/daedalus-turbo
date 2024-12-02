import React from 'react';
import SyncMessage from './Message.jsx';
import SyncPaperLink from './PaperLink.jsx';
import SyncTip from './Tip.jsx';
import SyncSettings from './Settings.jsx';

export default function SyncScreenSettings({ status, confirmReady, trackStatus }) {
    return <div className="sync screen">
        <div className="col">
            <div className="row">
                <div>
                    <img className="logo-large" src="static/logo.svg"/>
                </div>
            </div>
            <SyncTip status={status} />
            <SyncMessage status={status} />
            <SyncSettings status={status} confirmReady={confirmReady} trackStatus={trackStatus} />
            <SyncPaperLink />
        </div>
    </div>;
}
