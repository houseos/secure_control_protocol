import 'dart:convert';
import 'dart:math';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:test/test.dart';

class ScpCrypto {
  Future<String> decodeThenDecrypt(
      String key, String nvcn, String base64Text) async {
    List<int> decodedKey = base64.decode(key);
    List<int> decodedNvcn = base64.decode(nvcn);
    List<int> decodedText = base64.decode(base64Text);
    return await decryptMessage(decodedKey, decodedNvcn, decodedText);
  }

  Future<String> decryptMessage(
      List<int> key, List<int> nvcn, List<int> encryptedText) async {
    // Encode Key
    SecretKey secretKey = SecretKey(key);
    //Encode nonce
    Nonce nonce = Nonce(nvcn);
    //Encode encrypted text
    List<int> cipherText = encryptedText;
    // Decrypt
    final clearText = await chacha20Poly1305Aead
        .decrypt(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
    )
        .catchError((err) {
      print(err);
    });
    // Return text
    return utf8.decode(clearText);
  }

  Future<ScpJson> encryptThenEncode(
      String key, String nvcn, String message) async {
    EncryptedPayload encryptedPayload =
        await encryptMessage(key, nvcn, message);
    return ScpJson(
      key: base64Encode(utf8.encode(key)),
      nvcn: base64Encode(utf8.encode(nvcn)),
      encryptedPayload: encryptedPayload,
    );
  }

  Future<EncryptedPayload> encryptMessage(
      String key, String nvcn, String plainText) async {
    // Encode Key
    SecretKey secretKey = SecretKey(utf8.encode(key));
    //Encode nonce
    Nonce nonce = Nonce(utf8.encode(nvcn));
    //Encode encrypted text
    List<int> clearText = utf8.encode(plainText);
    // Decrypt
    final encryptedText = await chacha20Poly1305Aead.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
    );

    String base64Data =
        base64Encode(chacha20Poly1305Aead.getDataInCipherText(encryptedText));
    String base64Mac = base64Encode(
        chacha20Poly1305Aead.getMacInCipherText(encryptedText).bytes);

    return EncryptedPayload(
      base64Data: base64Data,
      dataLength:
          chacha20Poly1305Aead.getDataInCipherText(encryptedText).length,
      base64Mac: base64Mac,
      base64Combined: base64Encode(encryptedText),
    );
  }

  bool verifyHMAC(String content, String hmac) {
    //for now only with default password later the password stored for the device has to be extracted.
    SecretKey secretKey =
        SecretKey(utf8.encode('01234567890123456789012345678901'));
    var input = utf8.encode(content);
    final sink = Hmac(sha512).newSink(secretKey: secretKey);
    sink.add(input);
    sink.close();
    var mac = sink.mac;
    return ListEquality().equals(hexToBytes(hmac), mac.bytes);
  }
}

class EncryptedPayload {
  String base64Combined;
  String base64Data;
  int dataLength;
  String base64Mac;

  EncryptedPayload(
      {this.base64Data, this.dataLength, this.base64Mac, this.base64Combined});
}

class ScpJson {
  String key;
  String nvcn;
  EncryptedPayload encryptedPayload;

  ScpJson({this.key, this.nvcn, this.encryptedPayload});

  Map<String, dynamic> toJson() => {
        'key': key,
        'nvcn': nvcn,
        'payload': encryptedPayload.base64Data,
        'payloadLength': encryptedPayload.dataLength,
        'mac': encryptedPayload.base64Mac,
      };
}
