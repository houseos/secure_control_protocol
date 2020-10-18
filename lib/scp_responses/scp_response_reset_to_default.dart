/*
secure_control_protocol
ScpResponseResetToDefault Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';

class ScpResponseResetToDefault {
  static const String type = "security-reset-to-default";
  String deviceId;
  String result;

  ScpResponseResetToDefault({this.deviceId, this.result});

  static Future<ScpResponseResetToDefault> fromJson(
      var inputJson, String password) async {
    if (inputJson['response'] == null ||
        inputJson['response'] == '' ||
        inputJson['hmac'] == null ||
        inputJson['hmac'] == '') {
      return null;
    }
    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (ScpCrypto().verifyHMAC(response, hmac, password)) {
      var decodedPayload = base64Decode(response);
      var decodedJson = json.decode(utf8.decode(decodedPayload));
      if (decodedJson['type'] == type) {
        ScpResponseResetToDefault restartResponse = ScpResponseResetToDefault(
          deviceId: decodedJson['deviceId'],
          result: decodedJson['result'],
        );
        return restartResponse;
      }
    }
    return null;
  }
}