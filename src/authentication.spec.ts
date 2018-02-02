import {addAuthenticationAuthority} from '@sakuraapi/auth-native-authority/lib/src';
import {ObjectID}                   from 'bson';
import {decode}                     from 'jsonwebtoken';
import * as reqMock                 from 'request-promise-native';
import * as request                 from 'supertest';
import {dbs}                        from '../spec/config/dbs';
import {
  testSapi,
  testUrl
}                                   from '../spec/helpers/sakura-api';
import {
  addOAuthAuthenticationAuthority,
  IAuthenticationOAuthAuthorityOptions
}                                   from './authentication';

/**
 * Developer Notes:
 *
 * These tests are setup to mock interaction with Facebook, etc. If you want to run an integration test to make sure things are actually
 * working, then you need to:
 *
 * Facebook:
 *
 * (1) get the code by opening your browser and passing in https://www.facebook.com/v2.11/dialog/oauth?client_id={APP_ID_GOES_HERE}&redirect_uri=https://www.facebook.com/connect/login_success.html&scope=email&state=123&auth_type=rerequest
 *      - make sure to replace APP_ID_GOES_HERE with your facebook app ID
 *      - make sure your network tab is open in developer mode (Chrome)
 *      - look in the headers tab under Query String Parameters (Chrome)
 *
 * (2) select the specific test you want to run by changing the test from `it` to `fit`
 * (3) run: `FB_CODE=<code from above> npm test`,
 *      if you need to preserve the state of the database for examination: `FB_CODE=<code from above> npm run test:db`
 *
 * Remember, codes are one time use and they have a short expiration so you have to generate a new one for each test.
 */

describe('addOAuthAuthenticationAuthority', () => {

  const oAuthOptions: IAuthenticationOAuthAuthorityOptions = {
    authDbConfig: dbs.authentication,
    userDbConfig: dbs.user,
    oAuthProviders: {
      facebook: {
        acceptEmailVerification: true,
        clientId: '1479471138772917',
        clientSecret: '445b8af4ff822c2853cef8e857a43998',
        redirectUri: 'https://www.facebook.com/connect/login_success.html',
        scope: ['email'],
        fields: ['email', 'first_name', 'last_name'],
        acceptFields: {
          first_name: 'fn',
          last_name: 'ln',
          id: 'faceBookId'
        }
      }
    },
    onError: async (err) => {
      console.log(`\n------------------------SERVER_ERROR thrown`.red);
      console.log(err);
    }
  };

  const authNativeAuthorityOptions = {
    authDbConfig: dbs.authentication,
    userDbConfig: dbs.user,
    defaultDomain: 'default'
  };

  const code = process.env.FB_CODE || 'TEST';

  const sapi = testSapi({
    plugins: [{
      options: oAuthOptions,
      order: 1,
      plugin: addOAuthAuthenticationAuthority
    }, {
      options: authNativeAuthorityOptions,
      plugin: addAuthenticationAuthority
    }]
  });

  let TEST_EMAIL = 'george@washington';
  let TEST_FIRST_NAME = 'George';
  let TEST_LAST_NAME = 'Washington';
  let TEST_FB_ID = '0000000';
  let TEST_FB_ACCESS_TOKEN = 'TEST_ACCESS_TOKEN';

  beforeEach(async (done) => {
    await sapi.listen({bootMessage: ''});

    if (!process.env.SAVE_DB) {
      const col = sapi.dbConnections.getDb(dbs.user.db).collection(dbs.user.collection);
      await col.deleteMany({});
    }

    const realGet = reqMock.get;

    spyOn(reqMock, 'get').and.callFake(async (uri) => {

      // access_token lookup
      if (uri.includes('/oauth/access_token?')) {
        if (code === 'TEST') {
          // mock data
          return JSON.stringify({
            access_token: TEST_FB_ACCESS_TOKEN,
            token_type: 'bearer',
            expires_in: 5177845,
            auth_type: 'rerequest'
          });
        } else {
          // intercept real data
          const json = await realGet(uri);
          const obj = JSON.parse(json);
          TEST_FB_ACCESS_TOKEN = obj.access_token;
          return json;
        }
      }

      // profile lookup
      if (uri.includes('/me?')) {
        // mock data
        if (code === 'TEST') {
          // mock data
          return JSON.stringify({
            email: TEST_EMAIL,
            first_name: TEST_FIRST_NAME,
            last_name: TEST_LAST_NAME,
            id: TEST_FB_ID
          });
        } else {
          // intercept real data
          const json = await realGet(uri);
          const obj = JSON.parse(json);
          TEST_EMAIL = obj.email;
          TEST_FIRST_NAME = obj.first_name;
          TEST_LAST_NAME = obj.last_name;
          TEST_FB_ID = obj.id;
          return json;
        }
      }
    });

    done();
  });

  afterEach(async (done) => {
    await sapi.close();
    done();
  });

  it('returns 400 with no authority', async (done) => {

    try {
      await request(sapi.app)
        .post(testUrl('/auth/oauth/login', sapi))
        .type('application/json')
        .send({
          authority: '',
          code: '123'
        })
        .expect(400);
      done();
    } catch (err) {
      done.fail(err);
    }
  });

  it('returns 400 with no code', async (done) => {
    try {
      await request(sapi.app)
        .post(testUrl('/auth/oauth/login', sapi))
        .type('application/json')
        .send({
          authority: 'facebook',
          code: ''
        })
        .expect(400);
      done();
    } catch (err) {
      done.fail(err);
    }

  });

  describe('facebook', () => {
    it('returns a SakuraAPI token in exchange for facebook code', async (done) => {
      try {
        const response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        if (response.status !== 200) {
          console.log(`Error Response (${response.status}): %o`.yellow, response.body);
          return done.fail(response.body);
        }

        const issuer = sapi.config.authentication.jwt.issuer;
        const token: any = decode((response.body || {} as any).token[issuer]);

        expect(response.status).toBe(200);
        expect(token).toBeDefined();
        expect(token.email).toBe(TEST_EMAIL);
        expect(token.firstName).toBe(TEST_FIRST_NAME);
        expect(token.lastName).toBe(TEST_LAST_NAME);
        expect(token.iss).toBe(issuer);
        expect(token.aud).toBe(issuer);

        done();
      } catch (err) {
        done.fail(err);
      }
    });

    it('creates new user if user does not already exist', async (done) => {
      try {
        const response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        if (response.status !== 200) {
          console.log(`Error Response (${response.status}): %o`.yellow, response.body);
          return done.fail(response.body);
        }

        const issuer = sapi.config.authentication.jwt.issuer;
        const token: any = decode((response.body || {} as any).token[issuer]);

        const col = sapi.dbConnections.getDb(dbs.user.db).collection(dbs.user.collection);
        const user = await col.findOne({_id: new ObjectID(token.id)});

        expect(user).toBeDefined();
        expect(user.domain).toBe('default');
        expect(user.emailVerified).toBeTruthy();
        expect(user.email).toBe(TEST_EMAIL);
        expect(user.fn).toBe(TEST_FIRST_NAME);
        expect(user.ln).toBe(TEST_LAST_NAME);
        expect(user.faceBookId).toBe(TEST_FB_ID);


        done();
      } catch (err) {
        done.fail(err);
      }
    });

    it('creates new user if user does not already exist', async (done) => {

      try {
        const response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        if (response.status !== 200) {
          console.log(`Error Response (${response.status}): %o`.yellow, response.body);
          return done.fail(response.body);
        }

        const issuer = sapi.config.authentication.jwt.issuer;
        const token: any = decode((response.body || {} as any).token[issuer]);

        const col = sapi.dbConnections.getDb(dbs.user.db).collection(dbs.user.collection);
        const user = await col.findOne({_id: new ObjectID(token.id)});

        expect(user).toBeDefined();
        expect(user.domain).toBe('default');
        expect(user.emailVerified).toBeTruthy();
        expect(user.email).toBe(TEST_EMAIL);
        expect(user.fn).toBe(TEST_FIRST_NAME);
        expect(user.ln).toBe(TEST_LAST_NAME);
        expect(user.faceBookId).toBe(TEST_FB_ID);


        done();
      } catch (err) {
        done.fail(err);
      }
    });

    it('flags a newly created user as having been created anew', async (done) => {

      try {
        const response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        if (response.status !== 200) {
          console.log(`Error Response (${response.status}): %o`.yellow, response.body);
          return done.fail(response.body);
        }

        const issuer = sapi.config.authentication.jwt.issuer;
        const token: any = decode((response.body || {} as any).token[issuer]);

        expect(token.isNew).toBeTruthy();

        done();
      } catch (err) {
        done.fail(err);
      }
    });

    it('does not create a new user if user already exist', async (done) => {
      try {
        let response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        if (response.status !== 200) {
          console.log(`Error Response (${response.status}): %o`.yellow, response.body);
          return done.fail(response.body);
        }

        const col = sapi.dbConnections.getDb(dbs.user.db).collection(dbs.user.collection);

        let user = await col.find({email: TEST_EMAIL}).toArray();
        expect(user.length).toBe(1);

        const lastLogin = user[0].lastLoginFB;

        response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        if (response.status !== 200) {
          console.log(`Error Response (${response.status}): %o`.yellow, response.body);
          return done.fail(response.body);
        }

        user = await col.find({email: TEST_EMAIL}).toArray();
        expect(user.length).toBe(1);
        expect(user[0].lastLoginFB).not.toBe(lastLogin);

        done();
      } catch (err) {
        done.fail(err);
      }
    });

    it('handles facebook login on existing native account', async (done) => {
      try {
        let response = await request(sapi.app)
          .post(testUrl('/auth/native/', sapi))
          .type('application/json')
          .send({
            email: TEST_EMAIL,
            password: 'TEST',
            firstName: TEST_FIRST_NAME,
            lastName: TEST_LAST_NAME
          });

        const col = sapi.dbConnections.getDb(dbs.user.db).collection(dbs.user.collection);

        const user1 = await col.findOne({email: TEST_EMAIL});

        response = await request(sapi.app)
          .post(testUrl('/auth/oauth/login', sapi))
          .type('application/json')
          .send({
            authority: 'facebook',
            code
          });

        expect(response.status).toBe(200);

        let users = await col.find({email: TEST_EMAIL}).toArray();
        expect(users.length).toBe(1);

        let user2 = users[0];

        expect(user2._id.toString()).toBe(user1._id.toString());
        expect(user2.domain).toBe(user1.domain);
        expect(user2.pwSet.toString()).toBe(user1.pwSet.toString());
        expect(user2.emailVerified).toBe(true);
        expect(user2.email).toBe(user1.email);
        expect(user2.pw).toBe(user1.pw);
        expect(user2.fn).toBe(user1.fn);
        expect(user2.ln).toBe(user1.ln);
        expect(user2.pwStrength).toBe(user1.pwStrength);
        expect(user2.faceBookId).toBe(TEST_FB_ID);


        done();
      } catch (err) {
        done.fail(err);
      }

    });

    it('handles native login on existing facebook account', async (done) => {
      let response = await request(sapi.app)
        .post(testUrl('/auth/oauth/login', sapi))
        .type('application/json')
        .send({
          authority: 'facebook',
          code
        });

      expect(response.status).toBe(200);

      const col = sapi.dbConnections.getDb(dbs.user.db).collection(dbs.user.collection);
      const user1 = await col.findOne({email: TEST_EMAIL});

      await col.updateOne({_id: user1._id}, {
        // manually set the password to TEST -- normally the user would have had to request a password reset
        $set: {pw: '$2a$12$oDJxwr0kZ5V7Jnv6Vvy7/uhukOnbdbVd4hpHq1vf4qKulegvymhIC'}
      });

      response = await request(sapi.app)
        .post(testUrl('/auth/native/login', sapi))
        .type('application/json')
        .send({
          email: TEST_EMAIL,
          password: 'TEST'
        });

      expect(response.status).toBe(200);

      let users = await col.find({email: TEST_EMAIL}).toArray();
      expect(users.length).toBe(1);

      let user2 = users[0];

      expect(user2._id.toString()).toBe(user1._id.toString());
      expect(user2.domain).toBe(user1.domain);
      expect(user2.pwSet.toString()).toBe(user1.pwSet.toString());
      expect(user2.emailVerified).toBe(true);
      expect(user2.email).toBe(user1.email);
      expect(user2.pw).toBe('$2a$12$oDJxwr0kZ5V7Jnv6Vvy7/uhukOnbdbVd4hpHq1vf4qKulegvymhIC');
      expect(user2.fn).toBe(user1.fn);
      expect(user2.ln).toBe(user1.ln);
      expect(user2.pwStrength).toBe(user1.pwStrength);
      expect(user2.faceBookId).toBe(TEST_FB_ID);

      done();
    });
  });
});
