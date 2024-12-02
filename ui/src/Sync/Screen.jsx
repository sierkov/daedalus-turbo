import React from 'react';
import TransitionSimple from '../TransitionSimple.jsx';
import SyncScreenProgress from './ScreenProgress.jsx';
import SyncScreenSettings from './ScreenSettings.jsx';
import './Screen.scss';

export default function SyncScreen({ status, confirmReady, trackStatus }) {
    if (!status?.ready) {
        if (status?.progress && Object.keys(status?.progress).length)
            return <SyncScreenProgress status={status} />;
        return <TransitionSimple />;
    }
    return <SyncScreenSettings status={status} confirmReady={confirmReady} trackStatus={trackStatus} />;
}