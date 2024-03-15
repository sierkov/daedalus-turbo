module.exports = {
    moduleNameMapper: {
        '\\.(png|svg|ttf)$': '<rootDir>/__mocks__/file-mock.js',
        '\\.(scss)$': '<rootDir>/__mocks__/style-mock.js'
    },
    moduleDirectories: [
        "node_modules",
        __dirname
    ],
    testEnvironment: 'jsdom'
}