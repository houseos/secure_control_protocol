/*
secure_control_protocol
ScpResponseSetPassword Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp.dart';
import 'package:secure_control_protocol/scp_crypto.dart';

class ScpResponseSetPassword {
  static const String type = "security-pw-change";
  String deviceId;
  String currentPasswordNumber;
  String result;

  ScpResponseSetPassword(
      {this.deviceId, this.currentPasswordNumber, this.result});

  static Future<ScpResponseSetPassword> fromJson(
      var inputJson, String password) async {
    if (inputJson['response'] == null ||
        inputJson['response'] == '' ||
        inputJson['hmac'] == null ||
        inputJson['hmac'] == '') {
      Scp.getInstance().log(
          'ResponseSetPassword, response: ${inputJson['response']}, hmac: ${inputJson['hmac']}');
      return null;
    }
    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (ScpCrypto().verifyHMAC(response, hmac, password)) {
      var decodedPayload = base64Decode(response);
      var decodedJson = json.decode(utf8.decode(decodedPayload));
      if (decodedJson['type'] == type) {
        ScpResponseSetPassword setPasswordResponse = ScpResponseSetPassword(
          deviceId: decodedJson['deviceId'],
          currentPasswordNumber: decodedJson['currentPasswordNumber'],
          result: decodedJson['result'],
        );
        return setPasswordResponse;
      }
    }
    return null;
  }
}