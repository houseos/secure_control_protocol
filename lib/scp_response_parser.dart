/*
secure_control_protocol
ScpResponseParser Classes
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';
import 'dart:convert';

class ScpResponseDiscover {
  static const String type = "discover-response";
  String deviceId;
  String deviceType;
  int currentPasswordNumber;
  String hmac;

  ScpResponseDiscover(
      {this.deviceId, this.deviceType, this.currentPasswordNumber, this.hmac});

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  factory ScpResponseDiscover.fromJson(var json, List<ScpDevice> devices) {
    if (json['type'] == type) {
      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        currentPasswordNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      String password = null;
      if (devices != null) {
        password = devices
            .firstWhere(
                (element) => element.deviceId == discoverResponse.deviceId)
            .knownPassword;
      }

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${discoverResponse.deviceId}${discoverResponse.deviceType}${discoverResponse.currentPasswordNumber}',
          discoverResponse.hmac,
          password)) {
        return discoverResponse;
      }
    }
    return null;
  }
}

class ScpResponseFetchNvcn {
  static const String type = "security-fetch-nvcn";
  String deviceId;
  String nvcn;

  ScpResponseFetchNvcn({this.deviceId, this.nvcn});

  factory ScpResponseFetchNvcn.fromJson(var json) {
    if (json['type'] == type) {
      if (json['deviceId'] == null ||
          json['deviceId'] == '' ||
          json['nvcn'] == null ||
          json['nvcn'] == '') {
        return null;
      }

      ScpResponseFetchNvcn nvcnResponse = ScpResponseFetchNvcn(
        deviceId: json['deviceId'],
        nvcn: json['nvcn'],
      );

      return nvcnResponse;
    }
    return null;
  }
}

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
      print(
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

class ScpResponseSetWifiConfig {
  static const String type = "security-wifi-config";
  String deviceId;
  String result;

  ScpResponseSetWifiConfig({this.deviceId, this.result});

  static Future<ScpResponseSetWifiConfig> fromJson(
      var inputJson, String password) async {
    if (inputJson['response'] == null ||
        inputJson['response'] == '' ||
        inputJson['hmac'] == null ||
        inputJson['hmac'] == '') {
      print(
          'ResponseWifiConfig, response: ${inputJson['response']}, hmac: ${inputJson['hmac']}');
      return null;
    }
    String response = inputJson['response'];
    String hmac = inputJson['hmac'];

    // Check hmac before additional processing
    if (ScpCrypto().verifyHMAC(response, hmac, password)) {
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
    return null;
  }
}

class ScpResponseRestart {
  static const String type = "security-restart";
  String deviceId;
  String result;

  ScpResponseRestart({this.deviceId, this.result});

  static Future<ScpResponseRestart> fromJson(
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
        ScpResponseRestart restartResponse = ScpResponseRestart(
          deviceId: decodedJson['deviceId'],
          result: decodedJson['result'],
        );
        return restartResponse;
      }
    }
    return null;
  }
}

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

class ScpResponseParser {
  static ScpResponseDiscover parseDiscoverResponse(
      var response, List<ScpDevice> devices) {
    return ScpResponseDiscover.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), devices);
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

  static Future<ScpResponseControl> parseControlResponse(
      var response, String password) async {
    return await ScpResponseControl.fromJson(
        json.decode(utf8.decode(response.bodyBytes)), password);
  }
}
