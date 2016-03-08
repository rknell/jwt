/// Lightweight JSON Web Token (JWT) implementation.
///
/// ## Usage
///
///     void main() {
///       var builder = new JWTBuilder();
///       var token = builder
///         ..issuer = 'https://api.foobar.com'
///         ..expiresAt = new DateTime.now().add(new Duration(minutes: 3))
///         ..setClaim('data', {'userId': 836})
///         ..getToken(); // returns token without signature
///
///       var signer = new JWTHmacSha256Signer();
///       var signedToken = builder.getSignedToken(signer, 'sharedSecret');
///       print(signedToken); // prints encoded JWT
///       var stringToken = signedToken.toString();
///
///       var decodedToken = new JWT.parse(stringToken);
///       // Verify signature:
///       print(decodedToken.verify(signer, 'sharedSecret')); // true
///
///       // Validate claims:
///       var validator = new JWTValidator() // uses DateTime.now() by default
///         ..issuer = 'https://api.foobar.com'; // set claims you wish to validate
///       Set<String> errors = validator.validate(decodedToken);
///       print(errors); // (empty list)
///     }
///
/// See documentation for more details.
library corsac_jwt;

import 'dart:convert';

import 'package:crypto/crypto.dart' show HMAC, SHA256;

final _jsonToBase64 = JSON.fuse(UTF8.fuse(BASE64));

int _secondsSinceEpoch(DateTime dateTime) {
  return (dateTime.millisecondsSinceEpoch / 1000).floor();
}

class JWTError {
  final String message;
  JWTError(this.message);

  @override
  String toString() => message;
}

String _base64Padded(String value) {
  var mod = value.length % 4;
  if (mod == 0) {
    return value;
  } else if (mod == 3) {
    return value.padRight(value.length + 1, '=');
  } else if (mod == 2) {
    return value.padRight(value.length + 2, '==');
  } else {
    throw new FormatException('Could not parse Base64 encoded string.', value);
  }
}

// See details: https://tools.ietf.org/html/rfc4648#page-7
String _base64urlSafe(String value) {
  return value.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/// JSON Web Token.
class JWT {
  static const Iterable<String> reservedClaims = const [
    'iss',
    'aud',
    'iat',
    'exp',
    'nbf',
    'sub',
    'jti'
  ];

  Map<String, String> _headers;
  Map<String, dynamic> _claims;

  /// Contains original Base64 encoded token header.
  final String encodedHeader;

  /// Contains original Base64 encoded token payload (claims).
  final String encodedPayload;

  /// Contains original Base64 encoded token signature, or `null`
  /// if token is unsigned.
  final String signature;

  JWT._(this.encodedHeader, this.encodedPayload, this.signature) {
    try {
      /// Dart's built-in BASE64 codec needs padding (SDK 1.14).
      _headers = _jsonToBase64.decode(_base64Padded(encodedHeader));
      _claims = _jsonToBase64.decode(_base64Padded(encodedPayload));
    } catch (e) {
      throw new JWTError('Could not decode token string. Error: ${e}.');
    }
  }

  /// Parses [token] string and creates new instance of [JWT].
  /// Throws [JWTError] if parsing fails.
  factory JWT.parse(String token) {
    var parts = token.split('.');
    if (parts.length == 2) {
      return new JWT._(parts.first, parts.last, null);
    } else if (parts.length == 3) {
      return new JWT._(parts[0], parts[1], parts[2]);
    } else {
      throw new JWTError('Invalid token string format for JWT.');
    }
  }

  /// Algorithm used to sign this token. The value `none` means this token
  /// is not signed.
  ///
  /// One should not rely on this value to determine the algorithm used to sign
  /// this token.
  String get algorithm => _headers['alg'];

  /// The issuer of this token (value of standard `iss` claim).
  String get issuer => _claims['iss'];

  /// The audience of this token (value of standard `aud` claim).
  String get audience => _claims['aud'];
  int get issuedAt => _claims['iat'];
  int get expiresAt => _claims['exp'];
  int get notBefore => _claims['nbf'];
  String get subject => _claims['sub'];
  String get id => _claims['jti'];

  @override
  String toString() {
    var buffer = new StringBuffer();
    buffer.writeAll([encodedHeader, '.', encodedPayload]);
    if (signature is String) {
      buffer.writeAll(['.', signature]);
    }
    return buffer.toString();
  }

  bool verify(JWTSigner signer, secret) {
    var actualSignature =
        signer.sign(encodedHeader + '.' + encodedPayload, secret);
    // We don't know if original signature was encoded with standard Base64 or
    // the "url safe" version of it. So for consistency we compare
    // "url safe" versions.
    return (_base64urlSafe(actualSignature) == _base64urlSafe(signature));
  }

  dynamic getClaim(String s) => _claims[s];
}

/// Builder for JSON Web Tokens.
///
/// Tokens produced by this builder are always "url safe".
class JWTBuilder {
  final Map<String, dynamic> _claims = {};

  /// Token issuer (standard `iss` claim).
  void set issuer(String issuer) {
    _claims['iss'] = issuer;
  }

  void set audience(String audience) {
    _claims['aud'] = audience;
  }

  void set issuedAt(DateTime issuedAt) {
    _claims['iat'] = _secondsSinceEpoch(issuedAt);
  }

  void set expiresAt(DateTime expiresAt) {
    _claims['exp'] = _secondsSinceEpoch(expiresAt);
  }

  void set notBefore(DateTime notBefore) {
    _claims['nbf'] = _secondsSinceEpoch(notBefore);
  }

  void set subject(String subject) {
    _claims['sub'] = subject;
  }

  void set id(String id) {
    _claims['jti'] = id;
  }

  /// Sets value of private (custom) claim.
  ///
  /// One can not use this method to
  /// set values of standard (reserved) claims, [JWTError] will be thrown in such
  /// case.
  void setClaim(String name, value) {
    if (JWT.reservedClaims.contains(name.toLowerCase())) {
      throw new ArgumentError.value(
          name, 'name', 'Only custom claims can be set with setClaim.');
    }
    _claims[name] = value;
  }

  /// Builds and returns JWT. The token will not be signed.
  ///
  /// To create signed token use [getSignedToken] instead.
  JWT getToken() {
    var headers = {'typ': 'JWT', 'alg': 'none'};
    var encodedHeader = _jsonToBase64.encode(headers);
    var encodedPayload = _jsonToBase64.encode(_claims);
    return new JWT._(
        _base64urlSafe(encodedHeader), _base64urlSafe(encodedPayload), null);
  }

  /// Builds and returns signed JWT.
  ///
  /// The token will be signed with provided [signer] and [secret].
  /// To create unsigned token use [getToken].
  JWT getSignedToken(JWTSigner signer, secret) {
    var headers = {'typ': 'JWT', 'alg': signer.algorithm};
    var encodedHeader = _base64urlSafe(_jsonToBase64.encode(headers));
    var encodedPayload = _base64urlSafe(_jsonToBase64.encode(_claims));
    var body = encodedHeader + '.' + encodedPayload;
    var signature = _base64urlSafe(signer.sign(body, secret));
    return new JWT._(encodedHeader, encodedPayload, signature);
  }
}

/// Signer interface for JWT.
abstract class JWTSigner {
  String get algorithm;
  String sign(String body, secret);
}

/// Signer implementing HMAC encryption using SHA256 hashing.
class JWTHmacSha256Signer implements JWTSigner {
  @override
  String get algorithm => 'HS256';

  @override
  String sign(String body, String secret) {
    var secretBytes = UTF8.encode(secret);
    var hmac = new HMAC(new SHA256(), secretBytes);
    var data = UTF8.encode(body);
    hmac.add(data);
    var hash = hmac.close();
    return BASE64.encode(hash);
  }
}

/// Validator for JSON Web Tokens.
///
/// One must configure validator and provide values for claims that should be
/// validated, except for `iat`, `exp` and `nbf` claims - these are always
/// validated based on the value of [currentTime].
class JWTValidator {
  /// Current time used to validate token's `iat`, `exp` and `nbf` claims.
  final DateTime currentTime;
  String issuer;
  String audience;
  String subject;
  String id;

  /// Creates new validator. One can supply custom value for [currentTime]
  /// parameter, if not the `DateTime.now()` value is used by default.
  JWTValidator({DateTime currentTime})
      : currentTime = currentTime ?? new DateTime.now();

  /// Validates provided [token] and returns a list of validation errors.
  /// Empty list indicates there were no validation errors.
  ///
  /// If [signer] and [secret] parameters are provided then token signature
  /// will also be verified. Otherwise signature must be verified manually using
  /// [JWT.verify] method.
  Set<String> validate(JWT token, {JWTSigner signer, secret}) {
    var errors = new Set<String>();

    var currentTimestamp = _secondsSinceEpoch(currentTime);
    if (token.expiresAt is int && currentTimestamp >= token.expiresAt) {
      errors.add('The token has expired.');
    }

    if (token.issuedAt is int && currentTimestamp < token.issuedAt) {
      errors.add('The token issuedAt time is in future.');
    }

    if (token.notBefore is int && currentTimestamp < token.notBefore) {
      errors.add('The token can not be accepted due to notBefore policy.');
    }

    if (issuer is String && issuer != token.issuer) {
      errors.add('The token issuer is invalid.');
    }

    if (audience is String && audience != token.audience) {
      errors.add('The token audience is invalid.');
    }

    if (subject is String && subject != token.subject) {
      errors.add('The token subject is invalid.');
    }

    if (id is String && id != token.id) {
      errors.add('The token unique identifier is invalid.');
    }

    if (signer is JWTSigner &&
        secret != null &&
        !token.verify(signer, secret)) {
      errors.add('The token signature is invalid.');
    }

    return errors;
  }
}
