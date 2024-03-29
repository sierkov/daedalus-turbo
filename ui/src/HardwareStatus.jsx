import React from 'react';
import './HardwareStatus.scss';

export default function HardwareStatus({ hardware, summary })
{
    if (hardware) {
        let internet = hardware?.internet ?? "unknown";
        let threads = hardware?.threads + " threads" ?? "unknown";
        // show only peak values for internet and threads in the summary mode
        if (summary) {
            const [internetCur, internetMax] = internet.split('/', 2);
            internet = internetMax ?? internet;
            const [threadsCur, threadsMax] = threads.split('/', 2);
            threads = threadsMax ?? threads;
        }
        return <div className="hw-info">
            <div className="resource">
                <div className="name">Internet</div>
                <div className="value">{internet}</div>
            </div>
            <div className="resource">
                <div className="name">CPU</div>
                <div className="value">{threads}</div>
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
    }
    return <></>;
}