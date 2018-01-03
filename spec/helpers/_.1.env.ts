import 'colors';

process.env.NODE_ENV = 'local-test';
process.env.SAKURA_API_CONFIG = 'dist/spec/config/environment.json';
process.env.TEST_MONGO_DB_ADDRESS = process.env.TEST_MONGO_DB_ADDRESS || 'localhost';
process.env.TEST_MONGO_DB_PORT = process.env.TEST_MONGO_DB_PORT || '37001';

// tslint:disable-next-line:no-console
console.log((`NODE_ENV set to ${process.env.NODE_ENV}`.green));
