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
import 'package:secure_control_protocol/scp_responses/IValidatable.dart';
import 'package:secure_control_protocol/util/input_validation.dart';

class ScpResponseMeasure implements IValidatable {
  static const String type = "measure";
  String _action = '';
  String _deviceId = '';
  String _result = '';
  String _value = '';

  ScpResponseMeasure(
      {String action = '',
      String deviceId = '',
      String value = '',
      String result = ''}) {
    _action = action;
    _deviceId = deviceId;
    _value = value;
    _result = result;
  }

  static Future<ScpResponseMeasure> fromJson(var inputJson, String password)async {
    if (!InputValidation.validateJsonResponse(inputJson)) {
      return ScpResponseMeasure();
    }

    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (await ScpCrypto().verifyHMAC(response, hmac, password)) {
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
    return ScpResponseMeasure();
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

  String getValue() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _value;
    }
  }

  bool isValid() {
    if (_action != '' && _deviceId != '' && _result != '' && _value != '') {
      return true;
    }
    return false;
  }
}
