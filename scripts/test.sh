#!/usr/bin/env bash

set -ex
npm run docker:local-compose-up
npm run build
rsync -r --exclude=*.ts spec/config dist/spec
npx jasmine ; npm run docker:local-compose-down
