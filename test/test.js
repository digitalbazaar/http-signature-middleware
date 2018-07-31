/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const axios = require('axios');
const base64url = require('base64url');
const chai = require('chai');
const config = require('./config');
const fs = require('fs');
const helpers = require('./helpers');
const https = require('https');
const mockData = require('./mock-data');
const mockServer = require('./mock-server');
const should = chai.should();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

let server = null;

describe('http-signature-middleware', () => {
  before(callback => {
    const key = fs.readFileSync('./test/basic-server.key');
    const cert = fs.readFileSync('./test/basic-server.crt');
    server = https.createServer({cert, key}, mockServer.createServer());
    server.listen(config.port, callback);
  });

  after(callback => {
    server.close(callback);
  });

  it('dereferences an https ed25519 key', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/alpha`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    try {
      response = (await axios(requestOptions)).data;
    } catch(err) {
      should.not.exist(err);
    }
    response.should.be.an('object');
    response.success.should.be.true;
    response.id.should.equal(identity.id);
  });
  it('dereferences an https rsa key', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/alpha`,
    };
    const identity = mockData.identities.gamma;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'rsa-sha256', identity, requestOptions});
    let response;
    try {
      response = (await axios(requestOptions)).data;
    } catch(err) {
      should.not.exist(err);
    }
    response.should.be.an('object');
    response.success.should.be.true;
    response.id.should.equal(identity.id);
  });
  it('invokes an ocap', async () => {
    const requestOptions = {
      headers: {
        'object-capability':
          'type=ocapld; value=eyJpZCI6ICJ1cm46MTIzIn0; ' +
          `action=${base64url('foo')}`
      },
      method: 'GET',
      url: `https://localhost:${config.port}/ocap`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions,
        additionalIncludeHeaders: ['object-capability']});
    let response;
    try {
      response = (await axios(requestOptions)).data;
    } catch(err) {
      should.not.exist(err);
    }
    response.should.be.an('object');
    response.success.should.be.true;
    response.id.should.equal(identity.id);
  });
  it('fails to invoke an ocap because it is not signed', async () => {
    const requestOptions = {
      headers: {
        'object-capability': 'type=ocapld; value=eyJpZCI6ICJ1cm46MTIzIn0'
      },
      method: 'GET',
      url: `https://localhost:${config.port}/ocap`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain(
      '"Object-Capability" header specified but not signed');
  });
  it('fails to invoke an ocap because it is not found', async () => {
    const requestOptions = {
      headers: {
        'object-capability': 'type=ocapld; value=eyJpZCI6ICJ1cm46NDU2In0'
      },
      method: 'GET',
      url: `https://localhost:${config.port}/ocap`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions,
        additionalIncludeHeaders: ['object-capability']});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain('Object capability not found');
  });
  it('fails to invoke ocaps because one is not found', async () => {
    const requestOptions = {
      headers: {
        'object-capability': [
          'type=ocapld; value=eyJpZCI6ICJ1cm46MTIzIn0',
          'type=ocapld; value=eyJpZCI6ICJ1cm46NDU2In0'
        ]
      },
      method: 'GET',
      url: `https://localhost:${config.port}/ocap`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions,
        additionalIncludeHeaders: ['object-capability']});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain('Object capability not found');
  });
  it('fails to invoke an ocap because of a bad key type', async () => {
    const requestOptions = {
      headers: {
        'object-capability': 'type=ocapld; value=eyJpZCI6ICJ1cm46MTIzIn0'
      },
      method: 'GET',
      url: `https://localhost:${config.port}/ocap-bad-key-type`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions,
        additionalIncludeHeaders: ['object-capability']});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain('key is not a "CryptographicKey"');
  });
  it('uses `getKey` function to retrieve key', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/beta`,
    };
    const identity = mockData.identities.beta;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    try {
      response = (await axios(requestOptions)).data;
    } catch(err) {
      should.not.exist(err);
    }
    response.should.be.an('object');
    response.success.should.be.true;
    response.id.should.equal(identity.id);
  });
  it('fails if publicKey is not found', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/beta`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain('Key not found');
  });
  it('uses `getIdentity` function to retrieve identity', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/gamma`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    try {
      response = (await axios(requestOptions)).data;
    } catch(err) {
      should.not.exist(err);
    }
    response.should.be.an('object');
    response.success.should.be.true;
    response.id.should.equal(identity.id);
    should.exist(response.user);
    response.user.vip.should.be.true;
  });
  it('fails if identity is not found', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/gamma`,
    };
    const identity = mockData.identities.beta;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain('User not found');
  });
  it('fails if host header fails validation', async () => {
    // validator is expecting a `host` of `localhost`
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://127.0.0.1:${config.port}/alpha`,
    };
    const identity = mockData.identities.alpha;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.data.should.contain('Invalid host specified in the request');
  });
  it('fails if publicKey has been revoked', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/alpha`,
    };
    const identity = mockData.identities.delta;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'ed25519', identity, requestOptions});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.status.should.equal(500);
    err.response.data.should.contain('Public key has been revoked');
  });
  it('fails if algorithm does not match key type', async () => {
    const requestOptions = {
      headers: {},
      method: 'GET',
      url: `https://localhost:${config.port}/alpha`,
    };
    const identity = mockData.identities.gamma;
    await helpers.createHttpSignatureRequest(
      {algorithm: 'rsa-sha512', identity, requestOptions});
    let response;
    let err;
    try {
      response = await axios(requestOptions);
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.response.data.should.contain('does not match the public key type');
  });
});
