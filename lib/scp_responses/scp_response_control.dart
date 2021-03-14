/*
secure_control_protocol
ScpResponseDiscover Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_responses/IValidatable.dart';
import 'package:secure_control_protocol/util/input_validation.dart';

class ScpResponseControl implements IValidatable {
  static const String type = "control";
  String _action = '';
  String _deviceId = '';
  String _result = '';

  ScpResponseControl(
      {String action = '', String deviceId = '', String result = ''}) {
    _action = action;
    _deviceId = deviceId;
    _result = result;
  }

  static Future<ScpResponseControl> fromJson(var inputJson, String password) async {
    if (!InputValidation.validateJsonResponse(inputJson)) {
      return ScpResponseControl();
    }

    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (await ScpCrypto().verifyHMAC(response, hmac, password)) {
      var decodedPayload = base64Decode(response);

      var decodedJson = json.decode(utf8.decode(decodedPayload));
      if (decodedJson['type'] == type) {
        ScpResponseControl controlResponse = ScpResponseControl(
          action: decodedJson['action'],
          deviceId: decodedJson['deviceId'],
          result: decodedJson['result'],
        );
        return controlResponse;
      }
    }
    return ScpResponseControl();
  }

  String getAction() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _action;
    }
  }

  String getDeviceId() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _deviceId;
    }
  }

  String getResult() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _result;
    }
  }

  bool isValid() {
    if (_action != '' && _deviceId != '' && _result != '') {
      return true;
    }
    return false;
  }
}
