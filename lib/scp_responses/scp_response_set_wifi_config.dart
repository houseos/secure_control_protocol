/*
secure_control_protocol
ScpResponseSetWifiConfig Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_responses/validatable.dart';
import 'package:secure_control_protocol/util/input_validation.dart';

class ScpResponseSetWifiConfig {
  static const String type = "security-wifi-config";
  String _deviceId = '';
  String _result = '';

  ScpResponseSetWifiConfig({String deviceId = '', String result = ''}) {
    _deviceId = deviceId;
    _result = result;
  }

  static Future<ScpResponseSetWifiConfig> fromJson(
      var inputJson, String password) async {
    if (!InputValidation.validateJsonResponse(inputJson)) {
      return ScpResponseSetWifiConfig();
    }
    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (await ScpCrypto().verifyHMAC(response, hmac, password)) {
      var decodedPayload = base64Decode(response);
      var decodedJson = json.decode(utf8.decode(decodedPayload));
      if (decodedJson['type'] == type) {
        ScpResponseSetWifiConfig setWifiConfigResponse =
            ScpResponseSetWifiConfig(
          deviceId: decodedJson['deviceId'],
          result: decodedJson['result'],
        );
        return setWifiConfigResponse;
      }
    }
    return ScpResponseSetWifiConfig();
  }

  String getResult() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _result;
    }
  }

  String getDeviceId() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _deviceId;
    }
  }

  bool isValid() {
    if (_deviceId != '' && _result != '') {
      return true;
    }
    return false;
  }
}
