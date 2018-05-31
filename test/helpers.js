/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const httpSignatureHeader = require('http-signature-header');
const httpSignatureCrypto = require('http-signature-crypto');
const jsprim = require('jsprim');

const api = {};
module.exports = api;

// mutates requestOptions
api.createHttpSignatureRequest = async (
  {algorithm, identity, requestOptions}) => {
  if(!requestOptions.headers.date) {
    requestOptions.headers.date = jsprim.rfc1123(new Date());
  }
  const includeHeaders = ['date', 'host', '(request-target)'];
  const plaintext = httpSignatureHeader.createSignatureString(
    {includeHeaders, requestOptions});
  const keyId = identity.keys.publicKey.id;
  const authzHeaderOptions = {includeHeaders, keyId};
  const cryptoOptions = {plaintext};
  if(algorithm.startsWith('rsa')) {
    authzHeaderOptions.algorithm = algorithm;
    const alg = algorithm.split('-');
    const {privateKeyPem} = identity.keys.privateKey;
    cryptoOptions.algorithm = alg[0];
    cryptoOptions.privateKeyPem = privateKeyPem;
    cryptoOptions.hashType = alg[1];
  }
  if(algorithm === 'ed25519') {
    const {privateKeyBase58} = identity.keys.privateKey;
    cryptoOptions.algorithm = algorithm;
    cryptoOptions.privateKeyBase58 = privateKeyBase58;
  }

  authzHeaderOptions.signature = await httpSignatureCrypto.sign(cryptoOptions);
  requestOptions.headers.Authorization = httpSignatureHeader.createAuthzHeader(
    authzHeaderOptions);
};
