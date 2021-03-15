/*
secure_control_protocol
ScpResponseSetPassword Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_responses/validatable.dart';
import 'package:secure_control_protocol/util/input_validation.dart';

class ScpResponseSetPassword implements IValidatable {
  static const String type = "security-pw-change";
  String _deviceId = '';
  String _currentPasswordNumber = '';
  String _result = '';

  ScpResponseSetPassword(
      {String deviceId = '',
      String currentPasswordNumber = '',
      String result = ''}) {
    _deviceId = deviceId;
    _currentPasswordNumber = currentPasswordNumber;
    _result = result;
  }

  static Future<ScpResponseSetPassword> fromJson(var inputJson, String password) async {
    if (!InputValidation.validateJsonResponse(inputJson)) {
      return ScpResponseSetPassword();
    }

    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (await ScpCrypto().verifyHMAC(response, hmac, password)) {
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
    return ScpResponseSetPassword();
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

  String getCurrentPasswordNumber() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _currentPasswordNumber;
    }
  }

  bool isValid() {
    if (_deviceId != '' && _currentPasswordNumber != '' && _result != '') {
      return true;
    }
    return false;
  }
}
