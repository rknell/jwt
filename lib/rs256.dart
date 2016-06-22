/// Library implementing JWT RS256 signer.
library corsac_jwt.rs256;

import 'dart:typed_data';

import 'package:bignum/bignum.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:rsa_pkcs/rsa_pkcs.dart' as rsa;
import 'package:logging/logging.dart';
import 'corsac_jwt.dart';

Logger _logger = new Logger('JWTRsaSha256Signer');

class JWTRsaSha256Signer implements JWTSigner {
  final rsa.RSAPrivateKey _privateKey;
  final rsa.RSAPublicKey _publicKey;

  JWTRsaSha256Signer._(this._privateKey, this._publicKey);

  /// Creates new signer.
  ///
  /// [privateKey] is only required when signing new tokens and otherwise can
  /// be left as `null`. Similarly [publicKey] is only used to verify existing
  /// signatures.
  ///
  /// Both `privateKey` and `publicKey` are expected to be strings in PEM
  /// format.
  factory JWTRsaSha256Signer(
      {String privateKey, String publicKey, String password}) {
    rsa.RSAPKCSParser parser = new rsa.RSAPKCSParser();

    rsa.RSAPrivateKey priv;
    rsa.RSAPublicKey pub;
    if (privateKey is String) {
      rsa.RSAKeyPair pair = parser.parsePEM(privateKey, password: password);
      if (pair.private is! rsa.RSAPrivateKey)
        throw new JWTError('Invalid private RSA key.');
      priv = pair.private;
    }

    if (publicKey is String) {
      rsa.RSAKeyPair pair = parser.parsePEM(publicKey, password: password);
      if (pair.public is! rsa.RSAPublicKey)
        throw new JWTError('Invalid public RSA key.');
      pub = pair.public;
    }
    return new JWTRsaSha256Signer._(priv, pub);
  }

  @override
  String get algorithm => 'RS256';

  @override
  List<int> sign(List<int> body) {
    if (_privateKey == null) {
      throw new StateError(
          'RS256 signer requires private key to create signatures.');
    }
    var s = new Signer('SHA-256/RSA');
    var key = new RSAPrivateKey(_privateKey.modulus,
        _privateKey.privateExponent, _privateKey.prime1, _privateKey.prime2);
    var param = new ParametersWithRandom(
        new PrivateKeyParameter<RSAPrivateKey>(key),
        new SecureRandom("AES/CTR/PRNG"));

    s.init(true, param);
    RSASignature signature = s.generateSignature(new Uint8List.fromList(body));

    return signature.bytes.toList(growable: false);
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    if (_publicKey == null) {
      throw new StateError(
          'RS256 signer requires public key to verify signatures.');
    }

    try {
      var s = new Signer('SHA-256/RSA');
      var key = new RSAPublicKey(
          _publicKey.modulus, new BigInteger(_publicKey.publicExponent));
      var param = new ParametersWithRandom(
          new PublicKeyParameter<RSAPublicKey>(key),
          new SecureRandom("AES/CTR/PRNG"));

      s.init(false, param);
      var rsaSignature = new RSASignature(new Uint8List.fromList(signature));
      return s.verifySignature(new Uint8List.fromList(body), rsaSignature);
    } catch (e) {
      _logger.warning(
          'RS256 token verification failed with following error: ${e}.', e);
      return false;
    }
  }
}
