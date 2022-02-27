/*
secure_control_protocol
ScpResponseParser Classes
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_device.dart';

// SCP Responses
import 'package:secure_control_protocol/scp_responses/scp_response_discover.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_fetch_nvcn.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_rename.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_reset_to_default.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_restart.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_set_password.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_set_wifi_config.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_control.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_measure.dart';

class ScpResponseParser {
  static Future<ScpResponseDiscover> parseDiscoverResponseNoHmac(var response) async {
    return await ScpResponseDiscover.fromJson(
      jsonDecode(response),
      const [],
      false,
    );
  }

  static Future<ScpResponseDiscover> parseDiscoverResponse(
      var response, List<ScpDevice> devices, bool verifyHmac) async {
    return await ScpResponseDiscover.fromJson(
      jsonDecode(response),
      devices,
      verifyHmac,
    );
  }

  static Future<ScpResponseFetchNvcn> parseNvcnResponse(var response) async {
    return await ScpResponseFetchNvcn.fromJson(
      jsonDecode(response),
    );
  }

  static Future<ScpResponseSetPassword> parseSetPasswordResponse(
      var response, String password) async {
    return await ScpResponseSetPassword.fromJson(
      jsonDecode(response),
      password,
    );
  }

  static Future<ScpResponseSetWifiConfig> parseSetWifiConfigResponse(
      var response, String password) async {
    return await ScpResponseSetWifiConfig.fromJson(
      jsonDecode(response),
      password,
    );
  }

  static Future<ScpResponseRestart> parseRestartDeviceResponse(
      var response, String password) async {
    return await ScpResponseRestart.fromJson(
      jsonDecode(response),
      password,
    );
  }

  static Future<ScpResponseResetToDefault> parseResetToDefault(
      var response, String password) async {
    return await ScpResponseResetToDefault.fromJson(
      jsonDecode(response),
      password,
    );
  }

  static Future<ScpResponseRename> parseRename(
      var response, String password) async {
    return await ScpResponseRename.fromJson(
      jsonDecode(response),
      password,
    );
  }

  static Future<ScpResponseControl> parseControlResponse(
      var response, String password) async {
    return await ScpResponseControl.fromJson(
      jsonDecode(response),
      password,
    );
  }

  static Future<ScpResponseMeasure> parseMeasureResponse(
      var response, String password) async {
    return await ScpResponseMeasure.fromJson(jsonDecode(response), password);
  }

  static jsonDecode(var response) {
    return json.decode(utf8.decode(response.bodyBytes));
  }
}
