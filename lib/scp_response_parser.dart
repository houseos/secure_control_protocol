import 'dart:convert';
import 'package:secure_control_protocol/scp_crypto.dart';

class ScpResponseDiscover {
  static const String type = "discover-response";
  String deviceId;
  String deviceType;
  int currentPasswordNumber;
  String hmac;

  ScpResponseDiscover(
      {this.deviceId, this.deviceType, this.currentPasswordNumber, this.hmac});

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  factory ScpResponseDiscover.fromJson(var json) {
    if (json['type'] == type) {
      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        currentPasswordNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      // Check hmac before additional processing
      if (ScpCrypto().verifyHMAC(
          '${ScpResponseDiscover.type}${discoverResponse.deviceId}${discoverResponse.deviceType}${discoverResponse.currentPasswordNumber}',
          discoverResponse.hmac,
          null)) {
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

  ScpResponseSetWifiConfig(
      {this.deviceId, this.result});

  static Future<ScpResponseSetWifiConfig> fromJson(
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
        ScpResponseSetWifiConfig setWifiConfigResponse = ScpResponseSetWifiConfig(
          deviceId: decodedJson['deviceId'],
          result: decodedJson['result'],
        );
        return setWifiConfigResponse;
      }
    }
    return null;
  }
}

class ScpResponseParser {
  static ScpResponseDiscover parseDiscoverResponse(var response) {
    return ScpResponseDiscover.fromJson(
        json.decode(utf8.decode(response.bodyBytes)));
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
}
