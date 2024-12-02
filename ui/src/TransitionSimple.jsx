import React from "react";
import CircularProgress from "@mui/material/CircularProgress";
import './Transition.scss';

export default function TransitionSimple({ message })
{
    const msg = message ?? 'Please wait, operation in progress ...';
    return <div className="transition">
        <div>
            <CircularProgress />
        </div>
        <p className="explain">
            {msg}
        </p>
    </div>;
}
