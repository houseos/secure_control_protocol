/*
secure_control_protocol
ScpResponseParser Classes
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';

// SCP Responses
import 'package:secure_control_protocol/scp_responses/scp_response_discover.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_fetch_nvcn.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_reset_to_default.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_restart.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_set_password.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_set_wifi_config.dart';

class ScpResponseControl {
  static const String type = "control";
  String action;
  String deviceId;
  String result;

  ScpResponseControl({this.action, this.deviceId, this.result});

  static Future<ScpResponseControl> fromJson(
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
        ScpResponseControl controlResponse = ScpResponseControl(
          action: decodedJson['action'],
          deviceId: decodedJson['deviceId'],
          result: decodedJson['result'],
        );
        return controlResponse;
      }
    }
    return null;
  }
}

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

class ScpResponseParser {
  static ScpResponseDiscover parseDiscoverResponseNoHmac(
      var response, List<ScpDevice> devices) {
    return ScpResponseDiscover.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), devices, false);
  }

  static ScpResponseDiscover parseDiscoverResponse(
      var response, List<ScpDevice> devices) {
    return ScpResponseDiscover.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), devices, true);
  }

  static ScpResponseFetchNvcn parseNvcnResponse(var response) {
    return ScpResponseFetchNvcn.fromJson(
        json.decode(utf8.decode(response.bodyBytes)));
  }

  static Future<ScpResponseSetPassword> parseSetPasswordResponse(
      var response, String password) async {
    return await ScpResponseSetPassword.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }

  static Future<ScpResponseSetWifiConfig> parseSetWifiConfigResponse(
      var response, String password) async {
    return await ScpResponseSetWifiConfig.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }

  static Future<ScpResponseRestart> parseRestartDeviceResponse(
      var response, String password) async {
    return await ScpResponseRestart.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }

  static Future<ScpResponseResetToDefault> parseResetToDefault(
      var response, String password) async {
    return await ScpResponseResetToDefault.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }

  static Future<ScpResponseControl> parseControlResponse(
      var response, String password) async {
    return await ScpResponseControl.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }

  static Future<ScpResponseMeasure> parseMeasureResponse(
      var response, String password) async {
    return await ScpResponseMeasure.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }
}
