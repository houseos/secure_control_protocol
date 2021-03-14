/*
secure_control_protocol
ScpCrypto Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

// 3rd Party Libraries
import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:secure_control_protocol/scp.dart';
//import 'package:web3dart/crypto.dart';

// SCP
import 'package:secure_control_protocol/scp_json.dart';
import 'package:secure_control_protocol/util/encrypted_payload.dart';

class ScpCrypto {
  static final Random _random = Random.secure();

  static final String defaultPassword = '01234567890123456789012345678901';
  static const int PASSWORD_LENGTH = 32;
  static const int NONCE_LENGTH = 12;

  Future<String> decodeThenDecrypt(String key, String base64nonce,
      String base64mac, String base64Text, int payloadLength) async {
    Scp.getInstance().log('Nonce: $base64nonce');
    Scp.getInstance().log('base64mac: $base64mac');
    Scp.getInstance().log('base64Text: $base64Text');
    List<int> decodedKey = utf8.encode(key);
    List<int> decodedNonce = base64.decode(base64nonce);
    List<int> decodedText = base64.decode(base64Text);
    List<int> decodedMac = base64.decode(base64mac);
    Scp.getInstance().log('Text length: ${decodedText.length}');
    Scp.getInstance().log('Text length: $payloadLength');
    while (decodedText.length <= payloadLength) {
      decodedText.add(0);
    }
    Scp.getInstance().log('Decoded combined: $decodedText');
    return await decryptMessage(
        decodedKey, decodedNonce, decodedMac, decodedText);
  }

  Future<String> decryptMessage(List<int> key, List<int> nonceBytes,
      List<int> macBytes, List<int> encryptedText) async {
    // Initialize algorithm
    final algorithm = cryptography.Chacha20.poly1305Aead();
    // Initialize SecretBox
    final mac = cryptography.Mac(macBytes);
    final secretBox =
        cryptography.SecretBox(encryptedText, nonce: nonceBytes, mac: mac);
    // Encode Key
    final cryptography.SecretKey secretKey = cryptography.SecretKey(key);
    // Decrypt
    final clearText = await algorithm
        .decrypt(
      secretBox,
      secretKey: secretKey,
    )
        .catchError((err) {
      Scp.getInstance().log(err);
    });
    // Return text
    return utf8.decode(clearText);
  }

  Future<ScpJson> encryptThenEncode(String key, String message) async {
    EncryptedPayload encryptedPayload = await encryptMessage(key, message);
    return ScpJson(
      key: base64Encode(utf8.encode(key)),
      encryptedPayload: encryptedPayload,
    );
  }

  Future<EncryptedPayload> encryptMessage(String key, String plainText) async {

    // Initialize algorithm
    final algorithm = cryptography.Chacha20.poly1305Aead();

    // Encode Key
    cryptography.SecretKey secretKey = cryptography.SecretKey(utf8.encode(key));
    // Encode encrypted text
    List<int> clearText = utf8.encode(plainText);
    // Encrypt
    final nonce = algorithm.newNonce();
    final cryptography.SecretBox secretBox = await algorithm.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );

    String base64Data = base64Encode(secretBox.cipherText);
    String base64Mac = base64Encode(secretBox.mac.bytes);

    return EncryptedPayload(
      base64Data: base64Data,
      dataLength: secretBox.cipherText.length,
      base64Mac: base64Mac,
      base64Nonce: base64Encode(secretBox.nonce),
    );
  }

  Future<bool> verifyHMAC(String content, String hmac, String password) async {
    cryptography.SecretKey secretKey;
    if (password == '') {
      secretKey = cryptography.SecretKey(utf8.encode(defaultPassword));
    } else {
      secretKey = cryptography.SecretKey(utf8.encode(password));
    }

    var input = utf8.encode(content);
    final hmacAlgo = cryptography.Hmac.sha512();
    var mac = await hmacAlgo.calculateMac(input, secretKey: secretKey);
    return ListEquality().equals(hexToBytes(hmac), mac.bytes);
  }

  String generatePassword() {
    var values =
        List<int>.generate(PASSWORD_LENGTH, (i) => _random.nextInt(256));
    return base64Url.encode(values).substring(0, PASSWORD_LENGTH);
  }

  // EXTERNAL START
  // From web3dart package
  // SPDX-License-Identifier: MT
  // Copyright 2019 Simon Binder
  String strip0x(String hex) {
    if (hex.startsWith('0x')) return hex.substring(2);
    return hex;
  }

  Uint8List hexToBytes(String hexStr) {
    final bytes = hex.decode(strip0x(hexStr));
    if (bytes is Uint8List) return bytes;
    return Uint8List.fromList(bytes);
  }
  // EXTERNAL END
}
