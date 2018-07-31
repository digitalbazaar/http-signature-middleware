/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// FIXME: use did-io
const axios = require('axios');
const base64url = require('base64url');
const didio = {get: () => {}};
const httpSignatureHeader = require('http-signature-header');
const jsonld = require('jsonld');
const parseHttpHeader = require('parse-http-header');
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
    this.dereferenceUrlScheme = {
      did: this.getDidPublicKey.bind(this),
      https: this.getHttpsPublicKey.bind(this)
    };
  }

  async authenticate(req, options = {}) {
    // parse the req
    let parsed;
    try {
      parsed = httpSignatureHeader.parseRequest(req);
    } catch(err) {
      return this.fail(err);
    }

    const getKey = this.use('getKey');

    if(!getKey) {
      return this.error(new HttpSignatureError(
        'A `getKey` function must be defined.', 'InvalidStateError'));
    }

    let keyDoc;
    try {
      keyDoc = await getKey({req, keyId: parsed.keyId, parsed, options});
    } catch(err) {
      return this.error(err);
    }

    try {
      await this._verifySignature({keyDoc, parsed});
    } catch(err) {
      return this.error(err);
    }

    try {
      // handle parsing any object capabilities
      await this._parseObjectCapabilities({req, parsed, options});
    } catch(err) {
      return this.error(err);
    }

    const validateRequest = this.use('validateRequest');
    if(!validateRequest) {
      return this.error(new HttpSignatureError(
        'A `validateRequest` function must be defined.', 'InvalidStateError'));
    }
    try {
      await validateRequest({req, keyDoc, parsed, options});
    } catch(err) {
      return this.error(err);
    }

    if(req.capabilityInvocations) {
      const validateCapabilityInvocations = this.use(
        'validateCapabilityInvocations');
      if(!validateCapabilityInvocations) {
        return this.error(new HttpSignatureError(
          '"Object-Capability" header is not supported.', 'NotSupportedError'));
      }
      try {
        await validateCapabilityInvocations({req, keyDoc, parsed, options});
      } catch(err) {
        return this.error(err);
      }
    }

    const getUser = this.use('getUser') || this.getUser.bind(this);

    // getUser must throw error if the user/identity is not found
    let user;
    try {
      user = await getUser({req, keyDoc, parsed, options});
    } catch(err) {
      return this.error(err);
    }

    this.success(user);
  }

  async getUser({keyDoc}) {
    return {
      '@context': 'https://w3id.org/security/v2',
      id: keyDoc.owner
    };
  }

  // decides which scheme to use to look up the public key
  async ldGetKey({req, keyId, parsed, options = {}}) {
    // get scheme from public key ID (URL)
    let scheme = url.parse(keyId).protocol || ':';
    scheme = scheme.substr(0, scheme.length - 1);

    // get resolver for URL scheme
    const resolver = this.dereferenceUrlScheme[scheme];
    if(!resolver) {
      throw new HttpSignatureError(
        `URL scheme '${scheme}' is not supported.`, 'NotSupportedError');
    }

    const keyDoc = await resolver({req, keyId, parsed, options});

    // TODO: some of these checks might be common to the DID retrieval method,
    // evaluate the need for a common validation helper when the new did-io API
    // is implemented
    if(!(keyDoc && typeof keyDoc === 'object')) {
      throw new HttpSignatureError(
        'Public key document is invalid.', 'DataError');
    }

    // ensure key is not revoked
    if(keyDoc.revoked && _timestampBeforeNow(keyDoc.revoked)) {
      throw new HttpSignatureError(
        'Public key has been revoked.', 'InvalidStateError');
    }

    // ensure key is appropriately specified by key owner (run various
    // key checks via jsigs)
    const jsigs = this.use('jsigs');
    try {
      const checkOptions = {
        // support these key types by default
        keyType: options.keyType || [
          'CryptographicKey',
          'RsaVerificationKey2018',
          'Ed25519VerificationKey2018'
        ]
      };
      if(options.proof) {
        // pass custom proof through
        checkOptions.proof = options.proof;
      } else if(parsed.params.headers.includes('object-capability')) {
        checkOptions.proof = {
          'https://w3id.org/security#proofPurpose':
            'https://w3id.org/security#capabilityInvocation'
        };
      }
      await jsigs.checkKey(keyDoc, checkOptions);
    } catch(err) {
      throw new HttpSignatureError(
        `Public key verification failed: ${err}`,
        'DataError');
    }

    return keyDoc;
  }

  async getDidPublicKey({keyId}) {
    try {
      // TODO: utilize did-io API
      const keyDoc = await didio.get(keyId);
      return keyDoc;
    } catch(err) {
      throw new HttpSignatureError(
        'Public key URL unavailable.', 'NotFoundError');
    }
  }

  // 1. resolve key ID => should contain public key info including key material
  // (and owner)
  // 2. resolve owner ID and get identity info and list of public keys
  // 3. make sure key ID is listed in list of keys -- if so, verified
  async getHttpsPublicKey({keyId}) {
    try {
      const keyDoc = (await axios.get(keyId)).data;
      return keyDoc;
    } catch(err) {
      throw new HttpSignatureError(
        'Public key URL unavailable.', 'NotFoundError');
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

  async _parseObjectCapabilities({req, parsed, options}) {
    let ocapValue = req.header('object-capability');
    if(ocapValue) {
      if(!parsed.params.headers.includes('object-capability')) {
        throw new HttpSignatureError(
          '"Object-Capability" header specified but not signed.',
          'SyntaxError');
      }

      // parse ocaps
      if(typeof ocapValue === 'string') {
        ocapValue = [ocapValue];
      }
      const ocaps = ocapValue.map(parseHttpHeader);

      // resolve all ocaps
      const getOcap = this.use('getObjectCapability') || _getOcap;
      const resolved = [];
      for(const ocap of ocaps) {
        if(!(ocap.type && ocap.value)) {
          throw new HttpSignatureError(
            '"Object-Capability" header must include a "type" and a "value".',
            'SyntaxError');
        }

        // value must be base64url encoded
        let decoded;
        try {
          decoded = base64url.decode(ocap.value);
        } catch(e) {
          throw new HttpSignatureError(
            '"Object-Capability" header "value" encoding error.',
            'SyntaxError');
        }

        if(ocap.type === 'url') {
          // TODO: do better syntax validation as a URL on `decoded`
          // resolve ocap
          resolved.push(getOcap({id: decoded, parsed, options}));
        } else if(ocap.type === 'ocapld') {
          try {
            const x = JSON.parse(decoded);
            if(!(x && typeof x === 'object' && !Array.isArray(x))) {
              throw new Error('not an object');
            }
            resolved.push(x);
          } catch(e) {
            throw new HttpSignatureError(
              '"Object-Capability" decoded value must be a JSON object.',
              'SyntaxError');
          }
        } else {
          throw new HttpSignatureError(
            '"Object-Capability" header "type" must be "url" or "ocapld".',
            'SyntaxError');
        }
      }

      const capabilities = await Promise.all(resolved);

      // build capability invocations
      req.capabilityInvocations = capabilities.map((ocap, index) => {
        return {
          capability: ocap,
          action: ocaps[index].action || null
        };
      });
    }
  }

  // TODO: add public validateOcapLd helper API
};

function _getOcap() {
  return new HttpSignatureError(
    '"Object-Capability" decoded value must be a JSON object.',
    'NotSupportedError');
}

// returns true if the given timestamp is before the current time
function _timestampBeforeNow(timestamp) {
  if(!(typeof timestamp === 'string' && dateRegEx.test(timestamp))) {
    throw new TypeError('`revoked` timestamp must be a string.');
  }
  const now = new Date();
  const tsDate = new Date(timestamp);
  return tsDate < now;
}
