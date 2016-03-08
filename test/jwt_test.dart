library corsac_jwt.test;

import 'package:test/test.dart';
import 'package:corsac_jwt/corsac_jwt.dart';

int _secondsSinceEpoch(DateTime dateTime) {
  return (dateTime.millisecondsSinceEpoch / 1000).floor();
}

void main() {
  group('JWT:', () {
    DateTime now;
    JWTBuilder builder;

    setUp(() {
      now = new DateTime.now();
      builder = new JWTBuilder();
      builder
        ..issuer = 'https://mycompany.com'
        ..audience = 'people'
        ..issuedAt = now
        ..expiresAt = now.add(new Duration(seconds: 10))
        ..notBefore = now.add(new Duration(seconds: 5))
        ..id = 'identifier'
        ..subject = 'subj';
    });

    test('JWTBuilder can build unsigned token', () {
      var token = builder.getToken();
      expect(token, new isInstanceOf<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
    });

    test('JWTBuilder can build signed token', () {
      var signer = new JWTHmacSha256Signer();
      var token = builder.getSignedToken(signer, 'secret1');

      expect(token, new isInstanceOf<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.verify(signer, 'secret1'), isTrue);
      expect(token.verify(signer, 'invalid'), isFalse);
    });

    test('it parses string token', () {
      var signer = new JWTHmacSha256Signer();
      var stringToken =
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Y29tcGFueS5jb20ifQ==.db0dbAa1MSf9SYFxXq8Q0sd2/FDgKsgkzT8Z7tYX38c=';
      var token = new JWT.parse(stringToken);

      expect(token, new isInstanceOf<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.verify(signer, 'secret1'), isTrue);
      expect(token.verify(signer, 'invalid'), isFalse);
    });

    test('it parses urlSafe token (base64url encoded)', () {
      var signer = new JWTHmacSha256Signer();
      var stringToken =
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Zm9vYmFyLmNvbSIsImlhdCI6MTQ1NTIzMjI2NywiZXhwIjoxNDU1MjM0MDY3LCJuYmYiOjE0NTUyMzIyMzcsImJvZHkiOnsiYmxhaCI6ImJvb2EifX0.PXbDbE7YapU-6WvRqbdQ2OC1N2DScadvuQUqTHXopNc';
      var token = new JWT.parse(stringToken);

      expect(token, new isInstanceOf<JWT>());
      expect(token.issuer, equals('https://myfoobar.com'));
      expect(token.verify(signer, 'secret'), isTrue);
      expect(token.verify(signer, 'invalid'), isFalse);
    });

    test('it supports all standard claims', () {
      var token = builder.getToken();
      expect(token, new isInstanceOf<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.audience, equals('people'));
      expect(token.issuedAt, equals(_secondsSinceEpoch(now)));
      expect(token.expiresAt, equals(_secondsSinceEpoch(now) + 10));
      expect(token.notBefore, equals(_secondsSinceEpoch(now) + 5));
      expect(token.id, equals('identifier'));
      expect(token.subject, equals('subj'));
      expect(token.algorithm, equals('none'));
    });

    test('it supports custom (private) claims', () {
      builder
        ..issuer = 'https://foobar.com'
        ..setClaim('pld', 'payload')
        ..setClaim('map', {'key': 'value'});
      var token = builder.getToken();
      expect(token.issuer, equals('https://foobar.com'));
      expect(token.getClaim('pld'), equals('payload'));
      expect(token.getClaim('map'), equals({'key': 'value'}));

      var stringToken = token.toString();
      var parsedToken = new JWT.parse(stringToken);

      expect(parsedToken.issuer, equals('https://foobar.com'));
      expect(parsedToken.getClaim('pld'), equals('payload'));
      expect(parsedToken.getClaim('map'), equals({'key': 'value'}));
    });

    test('iss claim is validated', () {
      var token = builder.getToken();
      var time = new DateTime.now().add(new Duration(seconds: 6));
      var validator = new JWTValidator(currentTime: time)..issuer = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token issuer is invalid.'));

      validator.issuer = 'https://mycompany.com';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('exp claim is validated', () {
      var token = builder.getToken();
      var validator = new JWTValidator(
          currentTime: new DateTime.now().add(new Duration(seconds: 20)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token has expired.'));

      validator = new JWTValidator(
          currentTime: new DateTime.now().add(new Duration(seconds: 5)));
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('iat claim is validated', () {
      var token = builder.getToken();

      var validator = new JWTValidator(
          currentTime: new DateTime.now().subtract(new Duration(seconds: 1)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token issuedAt time is in future.'));

      var time = new DateTime.now().add(new Duration(seconds: 6));
      validator = new JWTValidator(currentTime: time);
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('nbf claim is validated', () {
      var token = builder.getToken();
      var validator = new JWTValidator(
          currentTime: new DateTime.now().add(new Duration(seconds: 1)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors,
          contains('The token can not be accepted due to notBefore policy.'));

      var time = new DateTime.now().add(new Duration(seconds: 6));
      validator = new JWTValidator(currentTime: time);
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('aud claim is validated', () {
      var token = builder.getToken();
      var time = new DateTime.now().add(new Duration(seconds: 6));
      var validator = new JWTValidator(currentTime: time)..audience = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token audience is invalid.'));

      validator.audience = 'people';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('sub claim is validated', () {
      var token = builder.getToken();
      var time = new DateTime.now().add(new Duration(seconds: 6));
      var validator = new JWTValidator(currentTime: time)..subject = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token subject is invalid.'));

      validator.subject = 'subj';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('jti claim is validated', () {
      var token = builder.getToken();
      var time = new DateTime.now().add(new Duration(seconds: 6));
      var validator = new JWTValidator(currentTime: time)..id = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token unique identifier is invalid.'));

      validator.id = 'identifier';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('signature is validated', () {
      var signer = new JWTHmacSha256Signer();
      var secret = 'secret';
      var token = builder.getSignedToken(signer, secret);
      var time = new DateTime.now().add(new Duration(seconds: 6));
      var validator = new JWTValidator(currentTime: time);
      var errors = validator.validate(token, signer: signer, secret: 'wrong');
      expect(errors, isNotEmpty);
      expect(errors, contains('The token signature is invalid.'));

      errors = validator.validate(token, signer: signer, secret: secret);
      expect(errors, isEmpty);
    });
  });
}
