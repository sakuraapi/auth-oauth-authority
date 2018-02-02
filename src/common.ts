import {SakuraApi}     from '@sakuraapi/core';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes
}                      from 'crypto';
import {
  Handler,
  Request,
  Response
}                      from 'express';
import {
  decode as decodeToken,
  sign as signToken
}                      from 'jsonwebtoken';
import {
  decode as urlBase64Decode,
  encode as urlBase64Encode,
  validate as urlBase64Validate
}                      from 'urlsafe-base64';
import * as uuid       from 'uuid';
import * as pwStrength from 'zxcvbn';


const IV_LENGTH = 16;

/**
 * Objects resolved in the Promise returned from [[IAuthenticationAuthorityOptions.onInjectCustomToken]].
 */
export interface ICustomTokenResult {
  /**
   * The JWT audience this token is being issued for.
   */
  audience: string;
  /**
   * The JWT (or really anything if your client knows how to deal with it).
   */
  token: string;
  /**
   * The JWT in its unencoded form. `auth-oauth-authority` logs tokens in the database upon their creation.
   * If you include `unEncodedToken`, it will log that. Otherwise, it logs the encoded token.
   */
  unEncodedToken?: any;
}

export interface IAuthorityOptions {

  /**
   * The database where authTokens are stored so that you have a record of tokes that are issued.
   */
  authDbConfig?: {
    collection: string;
    db: string;
  };

  /**
   * The exponent portion of how many rounds of hashing that bcrypt should go through. Defaults to 12 if not set. See:
   * https://github.com/kelektiv/node.bcrypt.js
   *
   * Set this to something high enough to thwart brute force attacks, but not so high that you cripple your server(s) under
   * the computational load.
   */
  bcryptHashRounds?: number;

  /**
   * Configuration for user creation
   */
  create?: {
    /**
     * An object of key / value pairs defining custom fields to store in the user collectiion. By default email and password
     * are stored (they're required) and domain is stored (if the feature is enabled). The keys should be the expected field
     * names in the json body. The values should be the database field names where the field should be stored. If you want to
     * have custom validation or manipulation of these fields, use [[onBeforeUserCreate]] and modify the `res.locals.reqBody`
     * object.
     */
    acceptFields?: any;
  };

  /**
   * If set, the system will require email & domain to login the user (a user can belong to multiple domains). If the domain
   * is not provided, this default value is substituted when looking up the user.
   */
  defaultDomain?: string;

  /**
   * Accepts a Express Handler, or an array of them, to run before user creation. This is helpful if you want to do
   * custom validation.
   */
  onBeforeUserCreate?: Handler | Handler[];

  /**
   * Called when the user changes his or her password, allowing the integrator to send an email
   * to the user notifying them of the password change.
   * @param user
   */
  onChangePasswordEmailRequest?: (user: any, req?: Request, res?: Response) => Promise<any>;

  /**
   * Called when there's an unrecognized error. If implemented, will be called when there's an unrecognized error. This gives you the
   * opportunity to hook errors into your logging system. The plugin will wait for a Promise.resolve() before continuing. If you
   * return a value in your promise, that will be substituted for the error body sent back to the client. If you do not implement
   * this hook, the plugin will resort to using console.log().
   * @param {Error} err
   * @returns {Promise<void>}
   */
  onError?: (err: Error) => Promise<void>;

  /**
   * Called when the user requests a "forgot password" email. It will generate a one time use password reset token. Only the
   * last one used is valid and it must be used within the time-to-live.
   * @param user
   * @param token
   */
  onForgotPasswordEmailRequest?: (user: any, token: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * Receives the current payload and the current db results from the user lookup. If you implement this, you should
   * modify the payload with whatever fields you need then resolve the promise with the new payload as the value. This
   * allows you to insert additional information in the resulting JWT token from whatever source you deem appropriate.
   * @param payload
   * @param dbResult
   */
  onJWTPayloadInject?: (payload: any, dbResult: any) => Promise<any>;

  /**
   * Called when a user has successfully logged in. Do whatever you need to, then either resolve the promise to
   * continue, or reject the promise with either the number 401 or 403 to send an unauthorized or forbidden
   * response. Any other rejection value will result in a 500. You can also reject with {statusCode:number,
   * message:string} to have the plugin send the statusCode and message as the response message.
   * @returns {Promise<void>}
   */
  onLoginSuccess?: (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => Promise<void>;

  /**
   * Called when the user needs the email verification key resent.. note that
   * @param user note: if the requested user doesn't exist, this will be undefined
   * @param emailVerificationKey note: if the requested user doesn't exist, this will be undefined
   */
  onResendEmailConfirmation?: (user: any, emailVerificationKey: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * If implemented, allows custom tokens to be included in the token dictionary sent back to an authenticated user
   * upon login.
   *
   * @param token The current token dictionary that's being returned to the authenticated user. This will contain the
   * tokens generated up to this point.
   * @param {string} key The private key that was used to generate the tokens in the token dictionary
   * @param {string} issuer The issuer that was used to generate the tokens in the token dictionary
   * @param {string} expiration The expiration that was used to generate the tokens in the token dictionary
   * @param payload The payload of the tokens generated in the token dictionary
   * @param {string} jwtId The id that was assigned to the tokens in the token dictionary up to this point
   * @returns {Promise<ICustomTokenResult[]>} A promise that should resolve an array of ICustomTokenResult which will
   * be used to add your custom tokens to the token dictionary returned to the user.
   */
  onInjectCustomToken?: (token: any, key: string, issuer: string, expiration: string, payload: any, jwtId: string)
    => Promise<ICustomTokenResult[]>;

  /**
   * Receives an object of the user just created. Of greatest importance here is validation key. You need to generate
   * an email and send that to the user in order for them to verify that they have access to the email address they're
   * claiming.
   * @param newUser an object of the user just created, minus the hashed password field.
   */
  onUserCreated?: (newUser: any, emailVerificationKey: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * The same database configuration that you're using for your model that represents the collection of MongoDB documents that
   * store your users.
   */
  userDbConfig?: {
    collection: string;
    db: string;
  };
}

export class JwtToken {
  constructor(private jwtAuthConfig: any,
              private options: IAuthorityOptions) {
  }

  async buildJwtToken(payload: any, logAuth: any, user: any, req: Request) {
    const key = this.jwtAuthConfig.key;
    const issuer = this.jwtAuthConfig.issuer;
    const exp = this.jwtAuthConfig.exp || '48h';

    if (!key || key === '' || !issuer || issuer === '') {
      return Promise
        .reject(new Error(`Unable to proceed, server misconfiguration. 'authentication.jwt.key' length?: ` +
          `'${key.length}' [note: value redacted for security], ` +
          `authentication.jwt.issuer value?: '${issuer || '>VALUE MISSING<'}'. These are required fields.`));
    }

    // self sign the payload - the issuer should never trust a token passed to it by an audience server since
    // they share a common private key - i.e., the audience server could be compromised and modify the token
    // before passing it to the issuing server. This only applies with server to server communication. For example,
    // Client authenticates with issuer, getting a key for an audience server. It passes the token to the audience
    // server, which then uses that token in a direct communication to the issuer. The client can't modify the
    // payload, but since the audience server has the private key, it could. The issSig allows the issuer to verify
    // that the payload hasn't been tampered with by the audience server.
    const hmac = createHmac('sha256', key);
    hmac.update(JSON.stringify(payload));
    (payload as any).issSig = hmac.digest('hex');

    const wait = [];
    const audiences = [];

    const jti = uuid();

    // Issuer Token
    wait.push(this.generateToken(key, issuer, issuer, exp, payload, jti));
    audiences.push(issuer);

    // Audience Tokens
    const audienceConfig = this.jwtAuthConfig.audiences;
    if (audienceConfig) {
      for (const jwtAudience of Object.keys(audienceConfig)) {
        const audienceKey = audienceConfig[jwtAudience];
        if (typeof audienceKey !== 'string') {
          return Promise.reject(new Error('Invalid authentication.jwt.audiences key defined. The value must be a '
            + 'secret key in the form of a string.'));
        }

        wait.push(this.generateToken(audienceKey, issuer, jwtAudience, exp, payload, jti));
        audiences.push(jwtAudience);
      }
    }

    const jwtTokens = await Promise.all(wait);
    const jwt = {};

    let i = 0;
    for (const result of jwtTokens) {
      jwt[audiences[i]] = result;
      i++;
    }

    const customTokens: ICustomTokenResult[] = (this.options.onInjectCustomToken)
      ? await this.options.onInjectCustomToken(jwt, key, issuer, exp, payload, jti)
      : [];


    const customTokensForLog = [];
    for (const customToken of customTokens) {
      jwt[customToken.audience] = customToken.token;

      customTokensForLog.push({
        audience: `${customToken.audience}`,
        token: customToken.unEncodedToken || customToken.token
      });
    }

    logAuth.userId = user.id;

    logAuth.token = [{
      audience: `${audiences.join(',')}`,
      token: decodeToken(jwtTokens[0])
    }, ...customTokensForLog];

    logAuth.ip = req.ip;
    logAuth.port = req.connection.remotePort;
    logAuth.url = req.originalUrl;
    logAuth.hostName = req.hostname;

    logAuth.audience = audiences;

    logAuth.jwTokenId = jti;
    logAuth.created = new Date();

    await logAuth.create();
    return jwt;
  }

  private generateToken(key: string, issuer: string, audience: string,
                        exp: string, payload: any, jti: string): Promise<string> {
    return new Promise((resolve, reject) => {
      signToken(payload, key, {
        audience,
        expiresIn: exp,
        issuer,
        jwtid: jti
      }, (err, token) => {
        if (err) {
          reject(err);
        }
        resolve(token);
      });
    });
  }
}

export function getPasswordStrength(password: string, user: any): number {

  const cd = []; // custom dictionary
  for (const key of Object.keys(user)) {
    const value = user[key];
    if (typeof value === 'string' && key !== 'password') {
      cd.push(user[key]);
    }
  }

  /** See: https://github.com/dropbox/zxcvbn
   * 0 # too guessable: risky password. (guesses < 10^3)
   * 1 # very guessable: protection from throttled online attacks. (guesses < 10^6)
   * 2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
   * 3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
   * 4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
   */
  const pwValue = ((password || {} as any).length > 99) ? password.substring(0, 99) : password;
  return pwStrength(pwValue, cd).score;
}


export async function encryptToken(key: string, keyContent: { [key: string]: any }): Promise<string> {
  try {
    const iv = randomBytes(IV_LENGTH);
    let cipher;

    try {
      cipher = createCipheriv('aes-256-gcm', key, iv);
    } catch (err) {
      throw new Error(`Invalid JWT private key set in SakuraApi's authorization.jwt.key setting: ${err}`);
    }

    const emailKeyBuffer = Buffer.concat([
      cipher.update(JSON.stringify(keyContent), 'utf8'),
      cipher.final()
    ]);
    const emailKeyHMACBuffer = cipher.getAuthTag();

    return `${urlBase64Encode(emailKeyBuffer)}.${urlBase64Encode(emailKeyHMACBuffer)}.${urlBase64Encode(iv)}`;
  } catch (err) {
    throw err;
  }
}

export async function decryptToken(key: string, tokenParts: any[]): Promise<any> {
  const tokenBase64 = tokenParts[0];
  const hmacBase64 = tokenParts[1];
  const ivBase64 = tokenParts[2];

  if (!urlBase64Validate(tokenBase64) || !urlBase64Validate(hmacBase64) || !urlBase64Validate(ivBase64)) {
    throw 403;
  }

  const encryptedToken = urlBase64Decode(tokenBase64);
  const hmacBuffer = urlBase64Decode(hmacBase64);
  const ivBuffer = urlBase64Decode(ivBase64);

  let token;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, ivBuffer);
    decipher.setAuthTag(hmacBuffer);
    const tokenBuffer = Buffer.concat([
      decipher.update(encryptedToken),
      decipher.final()
    ]);

    return JSON.parse(tokenBuffer.toString('utf8'));

  } catch (err) {
    throw 403;
  }
}
