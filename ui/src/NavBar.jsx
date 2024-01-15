import React from 'react';
import SearchBox from './SearchBox.jsx';
import './NavBar.scss';

export default function NavBar() {
    return <div className="nav-bar-container">
        <div className="nav-bar">
            <div className="logo">
                <a className="logo-link" href="#/"><img src="static/logo.svg" height="32" /></a>
            </div>
            <div className="search">
                <SearchBox noPadding />
            </div>
        </div>
    </div>;
}