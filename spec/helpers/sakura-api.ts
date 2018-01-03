import {SakuraApi} from '@sakuraapi/api';

import * as helmet from 'helmet';
import {sign} from 'jsonwebtoken';
import bodyParser = require('body-parser');

export const baseUri = '/testApi';
export const noNetwork = !!process.env.NO_NETWORK || false;

process.on('unhandledRejection', (err) => {
  console.log('Unhandled Rejection:'.red);
  console.log(err);
});

if (noNetwork) {
  // tslint:disable-next-line
  console.log('NO_NETWORK mode enabled'.yellow.underline);
}

export function skipNoNetwork(msg?: string) {
  if (noNetwork) {
    pending(msg || 'skipping, no network');
  }
}

export function testSapi(di?: { models?: any[], routables?: any[], plugins?: any[], services?: any[] }): SakuraApi {

  const sapi = new SakuraApi({
    baseUrl: '/testApi',
    configPath: 'dist/spec/config/environment.json',
    models: di.models,
    plugins: di.plugins,
    routables: di.routables
  });

  sapi.addMiddleware(helmet(), 0);
  sapi.addMiddleware(bodyParser.json(), 0);

  if (process.env.TRACE_REQ) {
    sapi.addMiddleware((req, res, next) => {
      // tslint:disable:no-console
      console.log(`REQUEST: ${req.method}: ${req.url} (${req.originalUrl}), body: ${JSON.stringify(req.body)}`.blue);
      // tslint:enable:no-console
      next();
    });
  }

  // not supported in SakuraApi 0.4.0 or the head of 0.5.0  -- integrate once 0.5.0 is released
  sapi.addLastErrorHandlers((err, req, res, next) => {

    // tslint:disable
    console.log('------------------------------------------------'.red);
    console.log('↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓'.zebra);
    console.log('An error bubbled up in an unexpected way during testing');
    console.log(err);
    console.log('↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑'.zebra);
    console.log('------------------------------------------------'.red);
    // tslint:enable

    next(err);
  });

  return sapi;
}

export function testUrl(endpoint: string, sapi: SakuraApi): string {
  return `${baseUri}${endpoint}`;
}

export function testToken(sapi: SakuraApi, obj?: any): any {
  const token = Object.assign(obj || {}, {
    aud: sapi.config.authentication.jwt.audience,
    iss: sapi.config.testSetup.jwt.issuer
  });

  return sign(token, sapi.config.authentication.jwt.key);
}
