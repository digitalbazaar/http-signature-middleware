/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// FIXME: use did-io
const axios = require('axios');
const didio = {get: () => {}};
const httpSignatureHeader = require('http-signature-header');
const jsonld = require('jsonld');
const signatureAlgorithms = require('signature-algorithms');
const url = require('url');
const {HttpSignatureError} = httpSignatureHeader;
const {Strategy} = require('passport-strategy');

// source: https://stackoverflow.com/a/3143231
const dateRegEx = /(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))/;

module.exports = class Middleware extends Strategy {
  constructor({name = 'http-signature-strategy'} = {}) {
    super();
    this.name = name;
    this._helpers = {};
    this.dereferenceUrlScheme = {did: true, https: true};
  }

  async authenticate(req) {
    const self = this;

    // parse the req
    let parsed;
    try {
      parsed = httpSignatureHeader.parseRequest(req);
    } catch(err) {
      return self.fail(err);
    }

    const publicKey = {id: parsed.keyId};

    const getKey = self.use('getKey');

    if(!getKey) {
      return self.error(new HttpSignatureError(
        'A `getKey` function must be defined.', 'InvalidStateError'));
    }

    let keyDoc;
    try {
      keyDoc = await getKey(publicKey);
    } catch(err) {
      return self.error(err);
    }

    try {
      await self._verifySignature({keyDoc, parsed});
    } catch(err) {
      return self.error(err);
    }

    const validateRequest = self.use('validateRequest');
    if(!validateRequest) {
      return self.error(new HttpSignatureError(
        'A `validateRequest` function must be defined.', 'InvalidStateError'));
    }
    try {
      await validateRequest(req);
    } catch(err) {
      return self.error(err);
    }

    const getUser = self.use('getUser') || self.getUser.bind(this);

    // getUser must throw error if the user/identity is not found
    let user;
    try {
      user = await getUser({keyDoc, req});
    } catch(err) {
      return self.error(err);
    }

    self.success(user);
  }

  async getUser({keyDoc}) {
    return {
      '@context': 'https://w3id.org/identity/v1',
      id: keyDoc.owner
    };
  }

  // decides which scheme to use to look up the public key
  async ldGetKey({id}) {
    const self = this;
    // get scheme from public key ID (URL)
    let scheme = url.parse(id).protocol || ':';
    scheme = scheme.substr(0, scheme.length - 1);
    // dereference URL if supported
    if(self.dereferenceUrlScheme[scheme]) {
      if(scheme === 'did') {
        return self.getDidPublicKey(id);
      }
      if(scheme === 'https') {
        return self.getHttpsPublicKey(id);
      }
    }
    throw new HttpSignatureError(
      `URL scheme '${scheme}' is not supported.`, 'NotSupportedError');
  }

  async getDidPublicKey(publicKeyId) {
    // TODO: utilized did-io API
    return didio.get(publicKeyId);
  }

  // 1. resolve key ID => should contain public key info including key material
  // (and owner)
  // 2. resolve owner ID and get identity info and list of public keys
  // 3. make sure key ID is listed in list of keys -- if so, verified
  async getHttpsPublicKey(publicKeyId) {
    const self = this;
    let keyDoc;
    try {
      keyDoc = await axios.get(publicKeyId).then(res => res.data);
    } catch(err) {
      throw new HttpSignatureError(
        'Public key URL unavailable.', 'NotFoundError');
    }

    // TODO: some of these checks might be common to the DID retrieval method,
    // evaluate the need for a common validation helper when the new did-io API
    // is implemented
    if(!(keyDoc && typeof keyDoc === 'object')) {
      throw new HttpSignatureError(
        'Public key document is invalid.', 'DataError');
    }

    if(keyDoc.revoked && _timestampBeforeNow(keyDoc.revoked)) {
      throw new HttpSignatureError(
        'Public key has been revoked.', 'InvalidStateError');
    }

    const jsigs = self.use('jsigs');
    try {
      await jsigs.checkKey(keyDoc);
    } catch(err) {
      throw new HttpSignatureError(
        `Public key verification failed: ${err}`,
        'DataError');
    }

    return keyDoc;

    // returns true if the given timestamp is before the current time
    function _timestampBeforeNow(timestamp) {
      if(!(typeof timestamp === 'string' && dateRegEx.test(timestamp))) {
        throw new TypeError('`revoked` timestamp must be a string.');
      }
      const now = new Date();
      const tsDate = new Date(timestamp);
      return tsDate < now;
    }
  }

  /**
   * Allows helpers to be set or retrieved.
   *
   * @param name the name of the helper to use
   * @param [helper] the api to set for the helper, only present for
   *          setter, omit for getter.
   *
   * @return the API for `name` if not using this method as a setter, otherwise
   *           undefined.
   */
  use(name, helper) {
    // setter mode
    if(helper) {
      this._helpers[name] = helper;
      return;
    }
    // getter mode:
    let h = this._helpers[name];
    if(h === undefined && ['jsigs'].includes(name)) {
      if(name === 'jsigs') {
        h = require('jsonld-signatures')();
      }
      this._helpers[name] = h;
    }
    return h;
  }

  async _verifySignature({keyDoc, parsed}) {
    const {publicKeyBase58, publicKeyPem} = keyDoc;
    const {signature} = parsed.params;
    const {signingString: plaintext} = parsed;
    const verifyOptions = {plaintext, signature};
    if(jsonld.hasValue(keyDoc, 'type', 'Ed25519VerificationKey2018')) {
      verifyOptions.algorithm = 'ed25519';
      verifyOptions.publicKeyBase58 = publicKeyBase58;
    } else if(jsonld.hasValue(keyDoc, 'type', 'RsaVerificationKey2018')) {
      if(parsed.algorithm && parsed.algorithm !== 'RSA-SHA256') {
        throw new HttpSignatureError(
          `The specified algorithm '${parsed.algorithm}' does not match the ` +
          'public key type: RsaVerificationKey2018.', 'InvalidStateError');
      }
      verifyOptions.algorithm = 'rsa';
      verifyOptions.hashType = 'sha256';
      verifyOptions.publicKeyPem = publicKeyPem;
    } else {
      throw new HttpSignatureError(
        'Public key document `type` must be one of: ' +
        'Ed25519VerificationKey2018, RsaVerificationKey2018.',
        'InvalidStateError');
    }

    let verified = false;
    try {
      verified = await signatureAlgorithms.verify(verifyOptions);
    } catch(err) {
      throw err;
    }
    if(!verified) {
      throw new HttpSignatureError(
        'Request signature verification failed.', 'NotAllowedError');
    }
  }
};
