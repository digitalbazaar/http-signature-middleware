/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const config = {
  port: 18443
};
module.exports = config;

const constants = config.constants = {CONTEXTS: {}};

constants.IDENTITY_CONTEXT_V1_URL = 'https://w3id.org/identity/v1';
constants.CONTEXTS[constants.IDENTITY_CONTEXT_V1_URL] = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'contexts/identity-v1.jsonld'),
    {encoding: 'utf8'}));
constants.SECURITY_CONTEXT_V1_URL = 'https://w3id.org/security/v1';
constants.CONTEXTS[constants.SECURITY_CONTEXT_V1_URL] = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'contexts/security-v1.jsonld'),
    {encoding: 'utf8'}));
constants.SECURITY_CONTEXT_V2_URL = 'https://w3id.org/security/v2';
constants.CONTEXTS[constants.SECURITY_CONTEXT_V2_URL] = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'contexts/security-v2.jsonld'),
    {encoding: 'utf8'}));
