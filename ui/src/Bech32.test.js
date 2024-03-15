import '@testing-library/jest-dom';
import * as React from 'react';
import { render, screen } from '@testing-library/react';
import Bech32 from './Bech32.jsx';
import Stake from './Stake.jsx';
import Pay from './Pay.jsx';

const mockUseNavigate = jest.fn();
const mockUseParams = jest.fn();
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useParams: () => mockUseParams(),
    useNavigate: () => mockUseNavigate
}));
import { MemoryRouter, Routes, Route } from 'react-router-dom';

test('Bech32 show error', () => {
    const addr = "addr1q86j2ywajjgswgg6a6j6rvf0kzhhrqlm";
    mockUseParams.mockReset().mockReturnValue({ bech32: addr });
    const { getByText } = render(<Bech32 />);
    expect(getByText('error parsing', { exact: false })).toBeInTheDocument();
});

test('Bech32 show alternatives', () => {
    const addr = "addr1q86j2ywajjgswgg6a6j6rvf0kzhhrqlma7ucx0f2w0v7stuau7usgm94re2n6fhe9ee88c2u5ta5znnwwtlxpsulzrdqv6rmuj";
    mockUseParams.mockReset();
    mockUseParams.mockReturnValue({ bech32: addr });
    const { getByText } = render(<Bech32 />);
    expect(getByText('has both payment and stake components', { exact: false })).toBeInTheDocument();
});

test('Bech32 stake redirect', () => {
    const addr = "stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg";
    mockUseParams.mockReset();
    mockUseParams.mockReturnValue({ bech32: addr });
    const { getByText } = render(<MemoryRouter history={history} initialEntries={[ '/bech32/' + addr ]}>
        <Routes>
            <Route path="/bech32/:bech32" element={<Bech32 />} />
            <Route path="/pay/:hash" element={<Pay />} />
            <Route path="/stake/:hash" element={<Stake />} />
        </Routes>
        <Bech32 />
    </MemoryRouter>);
    expect(getByText('Please wait', { exact: false })).toBeInTheDocument();
});