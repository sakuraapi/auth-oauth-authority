// tslint:disable:max-line-length
import {dbs} from './dbs';

module.exports = {
  dbConnections: [
    {
      name: dbs.user.db,
      url: `mongodb://${process.env.TEST_MONGO_DB_ADDRESS}:${process.env.TEST_MONGO_DB_PORT}/test`
    }, {
      name: dbs.authentication.db,
      url: `mongodb://${process.env.TEST_MONGO_DB_ADDRESS}:${process.env.TEST_MONGO_DB_PORT}/test`
    }
  ],
  authentication: {
    native: {
      bcryptHashRounds: 12,
      create: {
        acceptFields: {
          firstName: 'fn',
          lastName: 'ln',
          phone: 'ph'
        }
      }
    },
    jwt: {
      exp: '48h',
      issuer: 'oauth.sakuraapi.com',
      key: '12345678901234567890123456789012',
      fields: {
        fn: 'firstName',
        ln: 'lastName',
        _id: 'id'
      }
    }
  },
  server: {
    address: '127.0.0.1',
    port: 8777
  }
};
// tslint:enable:max-line-length
