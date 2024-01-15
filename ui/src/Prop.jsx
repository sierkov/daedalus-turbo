import React from 'react';
import './Prop.scss';

export default function Prop({ name, value, link, children }) {
    let valueDom = value && <span className="value">{value}</span>;
    if (link && value) valueDom = <span className="value"><a href={link}>{value}</a></span>;
    return <div className="row">
            <span className="name">{name}</span>
            {valueDom}
            {children}
        </div>;
}
