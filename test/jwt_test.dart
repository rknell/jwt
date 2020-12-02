library corsac_jwt.test;

import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:test/test.dart';

int _secondsSinceEpoch(DateTime dateTime) {
  return (dateTime.millisecondsSinceEpoch / 1000).floor();
}

void main() {
  group('$JWT', () {
    DateTime now;
    JWTBuilder builder;

    setUp(() {
      now = DateTime.now();
      builder = JWTBuilder();
      builder
        ..issuer = 'https://mycompany.com'
        ..audience = 'people'
        ..issuedAt = now
        ..expiresAt = now.add(Duration(seconds: 10))
        ..notBefore = now.add(Duration(seconds: 5))
        ..id = 'identifier'
        ..subject = 'subj';
    });

    test('JWTError toString', () {
      final error = JWTError('failed');
      expect(error.toString(), 'JWTError: failed');
    });

    test('JWTBuilder can build unsigned token', () {
      var token = builder.getToken();
      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
    });

    test('JWTBuilder can build signed token', () {
      var signer = JWTHmacSha256Signer('secret1');
      var token = builder.getSignedToken(signer);

      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.verify(signer), isTrue);
      expect(token.verify(JWTHmacSha256Signer('invalid')), isFalse);
    });

    test('it parses string token', () {
      var signer = JWTHmacSha256Signer('secret1');
      var stringToken =
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Y29tcGFueS5jb20ifQ.R7OVbiAKtvSkE-qF0fCkZP_m2JGrHobbRayHhEsKuKU';
      var token = JWT.parse(stringToken);

      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.verify(signer), isTrue);
      expect(token.verify(JWTHmacSha256Signer('invalid')), isFalse);
    });

    test('it parses another token', () {
      var signer = JWTHmacSha256Signer('secret');
      var stringToken =
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Zm9vYmFyLmNvbSIsImlhdCI6MTQ1NTIzMjI2NywiZXhwIjoxNDU1MjM0MDY3LCJuYmYiOjE0NTUyMzIyMzcsImJvZHkiOnsiYmxhaCI6ImJvb2EifX0.PXbDbE7YapU-6WvRqbdQ2OC1N2DScadvuQUqTHXopNc';

      var token = JWT.parse(stringToken);

      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://myfoobar.com'));
      expect(token.verify(signer), isTrue);
      expect(token.verify(JWTHmacSha256Signer('invalid')), isFalse);
      expect(token.toString(), stringToken);
    });

    test('it throws JWTError if token is invalid', () {
      var badToken1 =
          'invalid.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Y29tcGFueS5jb20ifQ.R7OVbiAKtvSkE-qF0fCkZP_m2JGrHobbRayHhEsKuKU';
      var badToken2 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid';
      expect(
          () => JWT.parse(badToken1), throwsA(const TypeMatcher<JWTError>()));
      expect(
          () => JWT.parse(badToken2), throwsA(const TypeMatcher<JWTError>()));
    });

    test('it supports all standard claims', () {
      var token = builder.getToken();
      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.audience, equals('people'));
      expect(token.issuedAt, equals(_secondsSinceEpoch(now)));
      expect(token.expiresAt, equals(_secondsSinceEpoch(now) + 10));
      expect(token.notBefore, equals(_secondsSinceEpoch(now) + 5));
      expect(token.id, equals('identifier'));
      expect(token.subject, equals('subj'));
      expect(token.algorithm, equals('none'));
    });

    test('it prevents setting standard claims using setClaim', () {
      expect(() => builder.setClaim('iss', 'bad'), throwsArgumentError);
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
      var parsedToken = JWT.parse(stringToken);

      expect(parsedToken.issuer, equals('https://foobar.com'));
      expect(parsedToken.getClaim('pld'), equals('payload'));
      expect(parsedToken.getClaim('map'), equals({'key': 'value'}));

      var claims = parsedToken.claims;

      expect(claims['pld'], equals('payload'));
      expect(claims['map'], equals({'key': 'value'}));

      claims['pld'] = 'good times!';
      expect(claims['pld'], equals('good times!'));
      expect(parsedToken.getClaim('pld'), equals('payload'));
    });

    test('it supports custom headers', () {
      builder
        ..issuer = 'https://foobar.com'
        ..setHeader('x5t', 'payload');
      var token = builder.getToken();
      expect(token.issuer, equals('https://foobar.com'));
      expect(token.headers['x5t'], equals('payload'));

      var stringToken = token.toString();
      var parsedToken = JWT.parse(stringToken);

      expect(parsedToken.issuer, equals('https://foobar.com'));
      expect(parsedToken.headers['x5t'], equals('payload'));
    });

    test('it throws error for updating reserved headers', () {
      expect(() {
        builder.setHeader('typ', 'error');
      }, throwsArgumentError);
    });

    test('validator uses current time by default', () {
      final validator = JWTValidator();
      expect(validator.currentTime, isNotNull);
    });

    test('iss claim is validated', () {
      var token = builder.getToken();
      var time = DateTime.now().add(Duration(seconds: 6));
      var validator = JWTValidator(currentTime: time)..issuer = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token issuer is invalid.'));

      validator.issuer = 'https://mycompany.com';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('exp claim is validated', () {
      var token = builder.getToken();
      var validator =
          JWTValidator(currentTime: DateTime.now().add(Duration(seconds: 20)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token has expired.'));

      validator =
          JWTValidator(currentTime: DateTime.now().add(Duration(seconds: 5)));
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('iat claim is validated', () {
      var token = builder.getToken();

      var validator = JWTValidator(
          currentTime: DateTime.now().subtract(Duration(seconds: 1)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token issuedAt time is in future.'));

      var time = DateTime.now().add(Duration(seconds: 6));
      validator = JWTValidator(currentTime: time);
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('nbf claim is validated', () {
      var token = builder.getToken();
      var validator =
          JWTValidator(currentTime: DateTime.now().add(Duration(seconds: 1)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors,
          contains('The token can not be accepted due to notBefore policy.'));

      var time = DateTime.now().add(Duration(seconds: 6));
      validator = JWTValidator(currentTime: time);
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('aud claim is validated', () {
      var token = builder.getToken();
      var time = DateTime.now().add(Duration(seconds: 6));
      var validator = JWTValidator(currentTime: time)..audience = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token audience is invalid.'));

      validator.audience = 'people';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('sub claim is validated', () {
      var token = builder.getToken();
      var time = DateTime.now().add(Duration(seconds: 6));
      var validator = JWTValidator(currentTime: time)..subject = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token subject is invalid.'));

      validator.subject = 'subj';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('jti claim is validated', () {
      var token = builder.getToken();
      var time = DateTime.now().add(Duration(seconds: 6));
      var validator = JWTValidator(currentTime: time)..id = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token unique identifier is invalid.'));

      validator.id = 'identifier';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('signature is validated', () {
      var signer = JWTHmacSha256Signer('secret');

      var token = builder.getSignedToken(signer);
      var time = DateTime.now().add(Duration(seconds: 6));
      var validator = JWTValidator(currentTime: time);
      var errors =
          validator.validate(token, signer: JWTHmacSha256Signer('invalid'));
      expect(errors, isNotEmpty);
      expect(errors, contains('The token signature is invalid.'));

      errors = validator.validate(token, signer: signer);
      expect(errors, isEmpty);
    });

    test('it provides read-only access to headers', () {
      builder..issuer = 'https://foobar.com';
      var token = builder.getToken();

      var headers = token.headers;
      expect(headers['typ'], 'JWT');
      expect(headers['alg'], 'none');
      expect(() {
        headers['kid'] = 'boom';
      }, throwsUnsupportedError);
    });
  });
}
