/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const config = require('./config');
const {constants} = config;
const express = require('express');
const jsonld = require('jsonld')();
const jsigs = require('jsonld-signatures');
const mockData = require('./mock-data');
const passport = require('passport');
const Middleware = require('..');

const api = {};
module.exports = api;

const app = express();

const nodeDocumentLoader = jsonld.documentLoaders.node({strictSSL: false});

jsonld.documentLoader = (url, callback) => {
  if(url in constants.CONTEXTS) {
    return callback(
      null, {
        contextUrl: null,
        document: constants.CONTEXTS[url],
        documentUrl: url
      });
  }
  nodeDocumentLoader(url, callback);
};

jsigs.use('jsonld', jsonld);

api.createServer = () => {
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    done(null, {});
  });

  const mwAlpha = new Middleware({name: 'ldBasic'});
  mwAlpha.use('jsigs', jsigs);
  mwAlpha.use('getKey', mwAlpha.ldGetKey.bind(mwAlpha));
  mwAlpha.use('validateRequest', _validateRequest);

  const mwBeta = new Middleware({name: 'customGetKey'});
  mwBeta.use('validateRequest', _validateRequest);
  mwBeta.use('getKey', async ({keyId}) => {
    if(keyId !== 'https://localhost:18443/keys/beta') {
      throw new Error(`Key not found: ${keyId}`);
    }
    const {publicKeyBase58} = mockData.identities.beta.keys.publicKey;
    return {
      '@context': constants.SECURITY_CONTEXT_V2_URL,
      type: ['CryptographicKey', 'Ed25519VerificationKey2018'],
      owner: `https://localhost:${config.port}/tests/i/beta`,
      label: 'Access Key 1',
      id: `https://localhost:${config.port}/keys/beta`,
      publicKeyBase58
    };
  });

  const mwGamma = new Middleware({name: 'customGetIdentity'});
  mwGamma.use('jsigs', jsigs);
  mwGamma.use('validateRequest', _validateRequest);
  mwGamma.use('getKey', mwGamma.ldGetKey.bind(mwGamma));
  mwGamma.use('getUser', async ({keyDoc}) => {
    const {owner: id} = keyDoc;
    if(id === 'https://localhost:18443/tests/i/alpha') {
      return {id, vip: true};
    }
    throw new Error(`User not found: ${id}`);
  });

  app.use(passport.initialize());
  passport.use(mwAlpha);
  passport.use(mwBeta);
  passport.use(mwGamma);

  function testEndpoint(req, res) {
    // console.log('USER INFO', req.user);
    const {user} = req;
    const {id} = user;
    res.json({id, success: true, user});
  }

  app.get('/alpha', passport.authenticate('ldBasic'), testEndpoint);
  app.get('/beta', passport.authenticate('customGetKey'), testEndpoint);
  app.get('/gamma', passport.authenticate('customGetIdentity'), testEndpoint);

  app.get('/tests/i/:ownerId', (req, res) => {
    const {ownerId} = req.params;
    res.json({
      '@context': constants.IDENTITY_CONTEXT_V1_URL,
      'id': `https://localhost/tests/i/${ownerId}`,
      'type': 'Identity',
      'publicKey': {
        'type': 'CryptographicKey',
        'owner': `https://localhost:${config.port}/tests/i/${ownerId}`,
        'label': 'Access Key 1',
        'id': `https://localhost:${config.port}/keys/${ownerId}`,
      }
    });
  });
  app.get('/keys/:keyId', (req, res) => {
    const {keyId} = req.params;
    const {publicKeyBase58, publicKeyPem, revoked} =
      mockData.identities[keyId].keys.publicKey;
    const keyDoc = {
      '@context': constants.SECURITY_CONTEXT_V2_URL,
      type: ['CryptographicKey'],
      owner: `https://localhost:${config.port}/tests/i/${keyId}`,
      label: 'Access Key 1',
      id: `https://localhost:${config.port}/keys/${keyId}`,
    };
    if(publicKeyBase58) {
      keyDoc.type.push('Ed25519VerificationKey2018');
      keyDoc.publicKeyBase58 = publicKeyBase58;
    }
    if(publicKeyPem) {
      keyDoc.type.push('RsaVerificationKey2018');
      keyDoc.publicKeyPem = publicKeyPem;
    }
    if(revoked) {
      const revoked = new Date();
      revoked.setDate(revoked.getDate() - 1);
      keyDoc.revoked = revoked.toISOString();
    }
    res.json(keyDoc);
  });

  app.use((err, req, res, next) => {
    //console.error(err);
    res.status(500).send(err.toString());
  });

  return app;
};

async function _validateRequest({req, options}) {
  const host = req.header('host');
  if(host !== `localhost:${config.port}`) {
    throw new Error(`Invalid host specified in the request: ${host}`);
  }
}
