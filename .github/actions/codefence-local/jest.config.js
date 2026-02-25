/** @type {import('ts-jest').JestConfigWithTsJest} */
const tsJest = require.resolve('ts-jest');

module.exports = {
  roots: ['<rootDir>'],
  transform: {
    '^.+\\.ts$': tsJest,
  },
  testRegex: '.*\\.spec\\.ts$',
  moduleFileExtensions: ['ts', 'js', 'json'],
  testEnvironment: 'node',
};
