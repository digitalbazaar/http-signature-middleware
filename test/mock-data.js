/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const config = require('./config');

const mock = {};
module.exports = mock;

mock.identities = {};

// valid identity with ed25519 keypair
mock.identities.alpha = {
  id: `https://localhost:${config.port}/tests/i/alpha`,
  keys: {
    publicKey: {
      id: `https://localhost:${config.port}/keys/alpha`,
      publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq',
    },
    privateKey: {
      privateKeyBase58:
        '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvM' +
        'JKk6QErH3wgdHp8itkSSiF',
    }
  }
};

// valid identity with ed25519 keypair
mock.identities.beta = {
  id: `https://localhost:${config.port}/tests/i/beta`,
  keys: {
    publicKey: {
      id: `https://localhost:${config.port}/keys/beta`,
      publicKeyBase58: 'BveYC5JaPU5zjNhqDHfVq1QRibbzAznNLfUigAibapXj',
    },
    privateKey: {
      privateKeyBase58:
        '3ztCNwkbzLXyAdtzz9RCEARixHmv8kLZS7Y1wrCw3byLGpUEPZ3bbYoUFsTMUv3wZ' +
        'H6f6eTUdp8YioDNjtBZtuqK',
    }
  }
};

// valid identity with rsa keypair
mock.identities.gamma = {
  id: `https://localhost:${config.port}/tests/i/gamma`,
  keys: {
    publicKey: {
      id: `https://localhost:${config.port}/keys/gamma`,
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwzPDp8kvJlGHbQGHQGcp\n' +
        'tO5iZG8iwED1QFNvJuKTZqYDoN44LUf95tYsjGqT38qj2/uo4zZRkfE3H1TEnsDo\n' +
        'KbbRn1mqV3098sU/G9Kk8fsXL9eJrQ77sLoDQmZf0/huIqHw6/jN7m5p3bq80A0m\n' +
        'gaJ56FuMq6IM4b9Sw40ajXTWQdiJqThN41eSHK01peT9jHMlnbQQwolqw0y9fkZ5\n' +
        'oEGHezQH6+CVRXB2u7WveMWvow3+ssGDwoK6/YeSWUXFv0VZoQwVO0VmaIFcM11f\n' +
        'G3KZD+iAayrF3xXz8ZPe0PY+6nZZi5/4HNy6B/30hAQn9X9I/0WMmmbQ5gCHJsu9\n' +
        'WwIDAQAB\n' +
        '-----END PUBLIC KEY-----\n',
    },
    privateKey: {
      privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIEpAIBAAKCAQEAwzPDp8kvJlGHbQGHQGcptO5iZG8iwED1QFNvJuKTZqYDoN44\n' +
        'LUf95tYsjGqT38qj2/uo4zZRkfE3H1TEnsDoKbbRn1mqV3098sU/G9Kk8fsXL9eJ\n' +
        'rQ77sLoDQmZf0/huIqHw6/jN7m5p3bq80A0mgaJ56FuMq6IM4b9Sw40ajXTWQdiJ\n' +
        'qThN41eSHK01peT9jHMlnbQQwolqw0y9fkZ5oEGHezQH6+CVRXB2u7WveMWvow3+\n' +
        'ssGDwoK6/YeSWUXFv0VZoQwVO0VmaIFcM11fG3KZD+iAayrF3xXz8ZPe0PY+6nZZ\n' +
        'i5/4HNy6B/30hAQn9X9I/0WMmmbQ5gCHJsu9WwIDAQABAoIBAESCMWP8xvCC4q3O\n' +
        'QILI8ilPFPc8zgx9f9XAsp0KHkODdniKJVs3DhRrDJ2Hdjiv7Qxy6ZY85Sn8Z6U2\n' +
        'Yf95osGpKS7tEEy+ZvSCZ6DDMCLBRiUDV42GWa1vy18NgQprAXRkM6MN4nCRDdTF\n' +
        'CilWxDHxLSnwn5FJQY4lUM3TAwOr5fBvSxjZiwDimykyy90wSqQxl1HI/badNipJ\n' +
        'ZDCoVdIDFtYjjD03o7wsyOPFxD0sZnKnxSIS8kYeHMxK5Js20eLdHRocZdSebxbu\n' +
        'bESUWaLg0sFn1tBg4y19hflAqzJGpta2wUombipkLm3DLJWQVMeq/52WJf7oqhr9\n' +
        'Fg1BxkECgYEA4JQ6i+XSxMkZnsk0vCjEEQH+lfixV9+dQ9tBmn+FqNKTV40gix8+\n' +
        'CMnB/ZKT6CknByQ1EojX7ZDj/c1qgoVYyRkcYcoQGzDwxZLydQpCncPT5/UYic0H\n' +
        '8eKUCQLzwOnZo55mBmehxTqTwmtYjoSCWsGWoGO7ssEGSa+rIYd4SqECgYEA3oNX\n' +
        'z53tE+Y8b7G95DEZIom32NpreMVq9T0xS8ZUYeDkR80a3Mli6IHz+qbFSd2ylcNf\n' +
        'PbnJ1xeEGyGgMi9PG4E7GWTitl68uAOKnZ/83nHNtXQ5SJwRtxPiOyuh+HN8AAqX\n' +
        'PfNCDffF6gAm+wfxyY1aAL04aBmzaaqEWpEGonsCgYEAxUqzHE+sl+ArN8l/IIWX\n' +
        'qXFdHJc8BPyXhhNKUNYSr7s+Yb3DhzTNJJ9KYt+wPFZayPVQApZhS3zsLf2VwlAv\n' +
        'LYt32ZjQCXM3MfrkMVnwJ/TvZml1Qynx/teUQU5soV9PKWRwMNQ906ygPj5br+hN\n' +
        'NDm5f/Hd5S2ZvoYrCuueC8ECgYEArKTZ3/PXu6Xa5IrTHBdgOiUCqVWnJ1h9iXQG\n' +
        'KJXkaOEWHgOswPvcKyyRQbxdvNcvtfWVkw3w5luPm4F2ixmb1mppkWVuZjORV3Ef\n' +
        '/vbgOzOveQeJXqYBNLxPvrs2+8+WuW1+NYnliXLic5HUrNdYKZrr50DpYBP42ZZ9\n' +
        'BMwbirsCgYA01XR+CS661Vy8bh6dEHa1IDoWBk3gqk9REUFnhdYLLEXy3zi1SnfI\n' +
        'mXm+fICVKinK5jKA/iu0M1zLUY/rWjpIWQTMpk9AcLhWYwURPCkLw/E//T5iaw37\n' +
        'cuRO/K57URWU78bQYpTMSCs0JhXnvHN1iCM5xyZ6rtz0jwZheWe+sA==\n' +
        '-----END RSA PRIVATE KEY-----\n',
    }
  }
};

// identity with a revoked ed25519 keypair
mock.identities.delta = {
  id: `https://localhost:${config.port}/tests/i/delta`,
  keys: {
    publicKey: {
      id: `https://localhost:${config.port}/keys/delta`,
      publicKeyBase58: 'Dkcrde4M4DCJF9JX7eZzbuMQcG61Mo25DJULUMVbe7ju',
      revoked: true,
    },
    privateKey: {
      privateKeyBase58:
        '5PQ55dQuYTF673hVBYez5fCVaDt9U6MXSR2JJb7NkRGN2Z3b9oGvU792LFA95CXKcK' +
        '7qqiin38m1pb7cxdww5mmH',
    }
  }
};
