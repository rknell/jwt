import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:corsac_jwt/rs256.dart';
import 'package:test/test.dart';
import 'dart:io';

void main() {
  group('RS256: ', () {
    JWTRsaSha256Signer signer;
    setUp(() {
      var priv = new File('test/resources/private.pem').readAsStringSync();
      var pub = new File('test/resources/public.pem').readAsStringSync();
      signer = new JWTRsaSha256Signer(priv, pub, null);
    });

    test('it can sign and verify JWT with RS256', () {
      var builder = new JWTBuilder();
      builder
        ..issuer = 'abc.com'
        ..expiresAt = new DateTime.now().add(new Duration(minutes: 3));
      var token = builder.getSignedToken(signer);

      expect(token.algorithm, 'RS256');
      expect(token.verify(signer), isTrue);
    });
  });
}
