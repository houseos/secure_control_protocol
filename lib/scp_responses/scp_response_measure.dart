/*
secure_control_protocol
ScpResponseMeasure Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';

class ScpResponseMeasure {
  static const String type = "measure";
  String action;
  String deviceId;
  String result;
  String value;

  ScpResponseMeasure({this.action, this.deviceId, this.value, this.result});

  static Future<ScpResponseMeasure> fromJson(
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
        ScpResponseMeasure measureResponse = ScpResponseMeasure(
          action: decodedJson['action'],
          deviceId: decodedJson['deviceId'],
          value: decodedJson['value'],
          result: decodedJson['result'],
        );
        return measureResponse;
      }
    }
    return null;
  }
}
