import {
  Db, IRoutableLocals, Json, Model, Routable, Route, SakuraApi, SakuraApiModel, SakuraApiPluginResult,
  SakuraApiRoutable
} from '@sakuraapi/api';
import {hash as bcryptHash} from 'bcrypt';
import {ObjectID} from 'bson';
import {NextFunction, Request, Response} from 'express';
import * as generatePassword from 'generate-password';
import * as request from 'request-promise-native';
import {encryptToken, getPasswordStrength, IAuthorityOptions, JwtToken} from './common';
import {BAD_REQUEST, OK, SERVER_ERROR, UNAUTHORIZED} from './http-status';


export interface IExpressParams {
  req: Request;
  res: Response;
  next: NextFunction;
}

export interface ILoginBody {
  domain?: string;
  authority?: string;
  code: string;
}

export interface IOAuthProviderConfig {
  acceptEmailVerification: true;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /**
   * The scope of permissions being requested (remember to include at least 'email' or user won't be able to login).
   * See:
   *    * https://developers.facebook.com/docs/facebook-login/permissions/
   */
  scope: string[];
  /**
   * The fields to request from the authority when doing the user's profile lookup to verify their identity. Remember to include
   * at least 'email' of the user won't be able to login.
   * See:
   *    * https://developers.facebook.com/docs/graph-api/reference/user/
   */
  fields?: string[];

  acceptFields?: {
    [key: string]: string
  }
}

export interface IFaceBookAccessTokenResponse {
  access_token: string;
  auth_type: string;
  expires_in: number;
  token_type: string;
}

export interface IFacebookProfile {
  id: string;
  name: string;
  email: string;
  first_name: string;
  last_name: string;
}

interface ILoginResult {
  jwt: any;
  user: any;
}

export interface IAuthenticationOAuthAuthorityOptions extends IAuthorityOptions {


  /**
   * Optionally override the various endpoints that make up the different parts of the native auth API. By default,
   * the following endpoints are assigned:
   *
   *    changePassword:          [put] auth/native/change-password
   *    create:                  [post] auth/native
   *    emailVerification:       [get] auth/native/confirm/:token
   *    forgotPassword:          [put] auth/native/forgot-password
   *    login:                   [post] auth/native/login
   *    newEmailVerificationKey: [post] auth/native/confirm
   *    resetPassword:           [put] auth/native/reset-password/:token
   *
   *    Remember, these are always built "on top" of your base url set in SakuraApi.
   *
   *    Note: if you don't include `:token` in `emailVerification` and `resetPassword`, you're going to have
   *    a bad time.
   */
  endpoints?: {
    login?: string;
  };

  /**
   * Lets you override the DB and JSON field names that the auth-oauth-authority plugin uses.
   */
  model?: {
    email?: {
      dbField?: string;
      jsonField?: string;
    },
    domain?: {
      dbField?: string;
      jsonField?: string;
    },
    password?: {
      dbField?: string;
    },
    passwordSet?: {
      dbField?: string;
    }
    emailVerified?: {
      dbField?: string;
      jsonField?: string;
    },
    lastLoginDb?: {
      dbField?: string;
    }
  };

  /**
   * Configuration for the oAuth authority. Currently, Facebook and Google are supported.
   */
  oAuthProviders?: {
    [service: string]: IOAuthProviderConfig
  }
}


/**
 * Adds native oAuth issuer capabilities to your SakuraAPI server.
 *
 * ### Example (sakura-api.ts)
 * <pre>
 *    ...
 *    addOAuthAuthenticationAuthority(sapi, {
 *      dbConfig: dbs.user
 *    });
 *    ...
 * </pre>
 *
 * This will add several endpoints to your server (subordinate to sapi.baseUrl):
 * * POST auth/native - attempts to authenticate a user based on the credentials provided and returns a JWT if authentication
 *   succeeds.
 *
 *   body content: {
 *      email: string,
 *      password: string,
 *      domain: string
 *   }
 *
 *
 * @param sapi your server's SakuraApi instance.
 * @param options
 */
export function addOAuthAuthenticationAuthority(sapi: SakuraApi, options: IAuthenticationOAuthAuthorityOptions): SakuraApiPluginResult {

  /***
   * Config setup
   ****************************************************************************************************************************************/
  if (!sapi) {
    throw new Error('auth-oauth-authority must have a valid instance of SakuraApi');
  }

  //// OAuth Config
  const oAuthConfig = ((sapi.config.authentication || {} as any).oAuth || {}) as IAuthenticationOAuthAuthorityOptions;

  const endpoints = options.endpoints || oAuthConfig.endpoints || {};

  // combine environment config with programmatic config
  options = Object.assign(oAuthConfig, options);

  // user db setings
  if (!options.userDbConfig || !options.userDbConfig.db || !options.userDbConfig.collection) {
    throw new Error('auth-oauth-authority addOAuthAuthenticationAuthority options parameter must have a valid ' +
      `'userDbConfig' configuration in 'IAuthenticationOAuthAuthorityOptions'.`);
  }

  // authentication db settings
  if (!options.authDbConfig || !options.authDbConfig.db || !options.authDbConfig.collection) {
    throw new Error('auth-oauth-authority addOAuthAuthenticationAuthority options parameter must have a valid ' +
      `'authDbConfig' configuration in 'IAuthenticationOAuthAuthorityOptions'.`);
  }

  // oAuth authority settings
  if (!options.oAuthProviders || Object.keys(options.oAuthProviders).length === 0) {
    throw new Error(`auth-oauth-authority addOAuthAuthenticationAuthority options parameter must have a valid ` +
      `'oAuthProviders' configuration in 'IAuthenticationOAuthAuthorityOptions'.`);
  }

  for (const key of Object.keys(options.oAuthProviders)) {
    const provider = options.oAuthProviders[key];
    if (!provider.clientId) {
      throw new Error(`oAuth authority '${key} requires a clientId'`);
    }
    if (!provider.clientSecret) {
      throw new Error(`oAuth authority '${key} requires a clientSecret'`);
    }
    if (!provider.redirectUri) {
      throw new Error(`oAuth authority '${key} requires a redirectUri'`);
    }
    if (!provider.scope || !Array.isArray(provider.scope) || provider.scope.indexOf('email') === -1) {
      throw new Error(`oAuth authority '${key} requires a scope and that scope needs to define at least email'`);
    }
  }

  //// JWT Config
  const jwtAuthConfig = (sapi.config.authentication || {} as any).jwt || null;
  if (!jwtAuthConfig) {
    throw new Error(`auth-oauth-authority requires SakuraApis configuration to have 'authentication.jwt' set.`);
  }

  if (!jwtAuthConfig.key) {
    throw new Error(`auth-oauth-authority requires SakuraApi's configuration to have 'authentication.jwt.key' set ` +
      'to a valid AES 256 private key');
  }

  if (jwtAuthConfig.key.length !== 32) {
    throw new Error(`auth-oauth-authority requires SakuraApi's configuration's 'authentication.jwt.key' to be ` +
      `be 32 characters long. The provided key is ${jwtAuthConfig.key.length} characters long`);
  }

  if (!jwtAuthConfig.issuer || jwtAuthConfig.issuer.length === 0) {
    throw new Error(`auth-oauth-authority requires SakuraApi's configuration's 'authentication.jwt.issuer' to be set`);
  }

  // Model Field Name Configuration
  const fields = {
    domainDb: ((options.model || {} as any).domain || {} as any).dbField || 'domain',
    domainJson: ((options.model || {} as any).domain || {} as any).jsonField || 'domain',
    emailDb: ((options.model || {} as any).email || {} as any).dbField || 'email',
    emailJson: ((options.model || {} as any).email || {} as any).jsonField || 'email',
    emailVerifiedDb: ((options.model || {} as any).emailVerified || {} as any).dbField || 'emailVerified',
    emailVerifiedJson: ((options.model || {} as any).emailVerified || {} as any).jsonField || 'emailVerified',
    lastLoginDb: ((options.model || {} as any).lastLogin || {} as any).dbField || 'lastLoginFB',
    passwordDb: ((options.model || {} as any).password || {} as any).dbField || 'pw',
    passwordSetDateDb: ((options.model || {} as any).passwordSet || {} as any).dbField || 'pwSet',
    passwordStrengthDb: ((options.model || {} as any).passwordStrength || {} as any).dbField || 'pwStrength'
  };

  /***
   * Models setup
   ****************************************************************************************************************************************/
  @Model({
    dbConfig: {
      collection: options.userDbConfig.collection,
      db: options.userDbConfig.db,
      promiscuous: true
    }
  })
  class OAuthAuthenticationAuthorityUser extends SakuraApiModel {
    @Db(fields.domainDb) @Json(fields.domainJson)
    domain: string = options.defaultDomain;

    @Db(fields.emailDb) @Json(fields.emailJson)
    email: string;

    @Db(fields.emailVerifiedDb) @Json(fields.emailVerifiedJson)
    emailVerified = false;

    @Db(fields.lastLoginDb)
    lastLogin: string;

    @Db({field: fields.passwordDb, private: true})
    password: string;

    @Db({field: fields.passwordSetDateDb})
    passwordSet = new Date();

    @Db({field: fields.passwordStrengthDb})
    passwordStrength: number;

  }

  @Model({
    dbConfig: {
      collection: options.authDbConfig.collection,
      db: options.authDbConfig.db,
      promiscuous: true
    }
  })
  class AuthenticationLog extends SakuraApiModel {
    @Db('uid') @Json()
    userId: ObjectID;

    @Db('jti') @Json()
    jwTokenId: string;

    @Db('tkn') @Json()
    token: any;

    @Db() @Json()
    created;

    @Db() @Json()
    authType = 'native';

    @Db() @Json()
    ip = '';

    @Db() @Json()
    port = null;

    @Db() @Json()
    url = '';

    @Db() @Json()
    hostName = '';

    @Db() @Json()
    invalidated = false;

    @Db() @Json()
    audience: any[] = [];
  }

  /***
   * Route setup
   ****************************************************************************************************************************************/
  @Routable({
    model: OAuthAuthenticationAuthorityUser,
    suppressApi: true
  })
  class AuthenticationOAuthAuthorityApi extends SakuraApiRoutable {

    /**
     * Login/create user
     */
    @Route({
      method: 'post',
      path: endpoints.login || 'auth/oauth/login'
    })
    async login(req: Request, res: Response, next: NextFunction): Promise<void> {

      const locals = res.locals as IRoutableLocals;
      const body = res.locals.reqBody as ILoginBody || {} as any;

      const authority = `${body.authority}`;
      const domain = `${body.domain || options.defaultDomain || 'default'}`;
      const code = `${body.code || ''}`;

      if (!authority || authority.length === 0) {
        locals.send(BAD_REQUEST, {error: 'authority is a required field, check body'});
      }

      if (!code || code.length === 0) {
        locals.send(BAD_REQUEST, {error: 'token is a required field, check body'});
        return next();
      }

      try {
        let token;

        switch (authority) {
          case 'facebook':
            token = await this.facebookLogin(code, domain, options.oAuthProviders[authority], {req, res, next});
            break;
          case 'google':
            token = await this.googleLogin(code, domain, options.oAuthProviders[authority], {req, res, next});
            break;
          default:
            throw 'INVALID_AUTHORITY';
        }

        if (options.onLoginSuccess) {
          await options.onLoginSuccess(token.user, token.jwt, sapi, req, res);
        }

        // set token to return to client
        locals.send(OK, {token: token.jwt});

        return next();
      } catch (err) {
        let errBody: any;
        switch (err) {
          case 'INVALID_AUTHORITY':
            locals.send(BAD_REQUEST, {error: 'authority is invalid, check body'});
            break;
          case 'INVALID_EMAIL':
            locals.send(UNAUTHORIZED, {
              error: 'user denied access to email address',
              code: 'INVALID_EMAIL'
            });
            break;
          case 'CODE_EXPIRED':
            locals.send(BAD_REQUEST, {error: 'CODE_EXPIRED'});
            break;
          case 'CODE_USED':
            locals.send(BAD_REQUEST, {error: 'CODE_USED'});
            break;
          case 'CODE_INVALID':
            locals.send(BAD_REQUEST, {error: 'CODE_INVALID'});
            break;
          case 'OAUTH_TOKEN_INVALID':
            errBody = (options.onError)
              ? await options.onError(err)
              : console.log(err);

            errBody = errBody || {error: 'OAUTH_TOKEN_INVALID'};
            locals.send(SERVER_ERROR, errBody);
            break;
          default:
            errBody = (options.onError)
              ? await options.onError(err)
              : console.log(err);

            errBody = errBody || {error: 'SERVER_ERROR'};
            locals.send(SERVER_ERROR, errBody);
            break;
        }
        return next();
      }
    }

    /**
     *
     * @param {string} code The code retrieved from Facebook that will be exchanged with an authentication token
     * @param {string} domain The domain of the user (for multi-tenant systems)
     * @param {IOAuthProviderConfig} authorityConfig
     * @param {Request} req
     * @returns {Promise<any>} JWT
     */
    private async facebookLogin(code: string, domain: string, authorityConfig: IOAuthProviderConfig, express: IExpressParams): Promise<ILoginResult> {

      const graphUri = `https://graph.facebook.com/v2.11`;

      const params = `client_id=${authorityConfig.clientId}` +
        `&redirect_uri=${authorityConfig.redirectUri}` +
        `&client_secret=${authorityConfig.clientSecret}` +
        `&code=${code}`;

      let token: IFaceBookAccessTokenResponse;
      try {
        token = JSON.parse(await request.get(`${graphUri}/oauth/access_token?${params}`));
      } catch (err) {
        if (err.statusCode === 400 && err.error.includes('This authorization code has expired')) {
          throw 'CODE_EXPIRED';
        } else if (err.statusCode === 400 && err.error.includes('This authorization code has been used')) {
          throw 'CODE_USED';
        } else if (err.statusCode === 400 && err.error.includes('Invalid verification code format')) {
          throw 'CODE_INVALID';
        } else {
          throw err;
        }
      }

      let profile: IFacebookProfile;
      try {
        authorityConfig.fields = authorityConfig.fields || ['email'];
        profile = JSON.parse(await request.get(`${graphUri}/me?fields=${authorityConfig.fields.join(',')}&access_token=${token.access_token}`));
      } catch (err) {
        if (err.statusCode === 400 && err.error.includes('Invalid OAuth access token')) {
          throw 'OAUTH_TOKEN_INVALID';
        } else {
          throw err;
        }
      }

      if (!profile.email || profile.email === '') {
        throw new Error('INVALID_EMAIL');
      }

      return await this.createAndOrLogin(profile, domain, authorityConfig, express);
    }

    private async googleLogin(token: string, domain: string, authorityConfig: IOAuthProviderConfig, express: IExpressParams) {

    }

    private async createAndOrLogin(profile: any, domain: string, authorityConfig: IOAuthProviderConfig, express: IExpressParams): Promise<ILoginResult> {

      const query = {
        [fields.emailDb]: profile.email,
        [fields.domainDb]: domain
      };

      let dbDoc = await OAuthAuthenticationAuthorityUser.getCursor(query).limit(1).next();
      let user: OAuthAuthenticationAuthorityUser = OAuthAuthenticationAuthorityUser.fromDb(dbDoc);

      let payload = {
        [fields.emailJson]: profile.email,
        [fields.domainJson]: domain
      };


      if (!user) {
        payload['isNew'] = true;
        user = await this.createUser(profile, domain, authorityConfig, express);
      }

      // Allows the inclusion of other fields in the resulting JWT from the User collection in MongoDB
      const fieldInclusion = ((sapi.config.authentication || {} as any).jwt || {} as any).fields;

      if (fieldInclusion) {
        for (const dbField of Object.keys(fieldInclusion)) {
          const payloadField = fieldInclusion[dbField];

          if (typeof payloadField !== 'string') {
            throw new Error(`unable to proceed, server misconfiguration. authentication.jwt.fields must be a key value pair ` +
              `of strings. key '${dbField}' has a value typeof '${typeof payloadField}'`);
          }

          payload[payloadField] = user[dbField];
        }
      }

      if (options.onJWTPayloadInject) {
        payload = await options.onJWTPayloadInject(payload, dbDoc);
      }

      // update DB
      const userUpdate = {};
      if (authorityConfig.acceptEmailVerification) {
        userUpdate[fields.emailVerifiedDb] = true;
      }
      if ((authorityConfig.acceptFields || {} as any).id) { // update Facebook ID if missing from user and set to be persisted
        userUpdate[authorityConfig.acceptFields.id] = profile.id;
      }
      userUpdate[fields.lastLoginDb] = new Date();

      await user.save(userUpdate);

      return {
        jwt: await new JwtToken(jwtAuthConfig, options)
          .buildJwtToken(payload,
            new AuthenticationLog(),
            user,
            express.req),
        user
      };
    }

    private async createUser(profile: any, domain: string, authorityConfig: IOAuthProviderConfig, express: IExpressParams): Promise<OAuthAuthenticationAuthorityUser> {

      const password = generatePassword.generate({
        length: 20,
        numbers: true,
        symbols: true,
        strict: true
      });
      const pwHash = await bcryptHash(password, options.bcryptHashRounds || 12);

      let user = new OAuthAuthenticationAuthorityUser();
      user.email = profile.email;
      user.password = pwHash;
      user.domain = domain;
      user.passwordSet = new Date();
      user[fields.emailVerifiedDb] = false;

      // insert custom fields
      if (authorityConfig.acceptFields) {
        for (const jsonField of Object.keys(authorityConfig.acceptFields)) {
          if (profile[jsonField] === undefined) {
            continue;
          }
          user[authorityConfig.acceptFields[jsonField]] = profile[jsonField];
        }
      }

      user.passwordStrength = getPasswordStrength(password, user);

      await user.create();
      const emailVerificationKey = await encryptToken(jwtAuthConfig.key, {userId: user.id});

      if (options.onUserCreated && typeof options.onUserCreated === 'function') {
        await options.onUserCreated(user.toJson(), emailVerificationKey, express.req, express.res);
      }

      return user;
    }
  }


  /***
   * Plugin results
   ****************************************************************************************************************************************/
  return {
    models: [
      AuthenticationLog,
      OAuthAuthenticationAuthorityUser
    ],
    routables: [
      AuthenticationOAuthAuthorityApi
    ]
  };
}


