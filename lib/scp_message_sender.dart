/*
secure_control_protocol
ScpMessageSender Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// 3rd Party Libraries
import 'package:http/http.dart' as http;

// SCP
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';
import 'package:secure_control_protocol/scp_response_parser.dart';
import 'package:secure_control_protocol/scp_status.dart';

// SCP Util
import 'package:secure_control_protocol/scp_json.dart';

// SCP Responses
import 'package:secure_control_protocol/scp_responses/scp_response_fetch_nvcn.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_reset_to_default.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_restart.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_set_password.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_set_wifi_config.dart';
import 'package:secure_control_protocol/scp_responses/scp_response_control.dart';

class ScpMessageSender {
  static const int PORT = 19316;
  static const int DISCOVER_TIMEOUT = 10;
  static const int NVCN_TIMEOUT = 10;
  static const int NEW_PASSWORD_TIMEOUT = 10;
  static const int SET_WIFI_CREDS_TIMEOUT = 30;
  static const int CONTROL_TIMEOUT = 30;
  static const int RESTART_TIMEOUT = 30;
  static const int RESET_TO_DEFAULT_TIMEOUT = 30;

  static sendDiscoverHello(String ip) async {
    return await http
        .get(
            'http://$ip:$PORT/secure-control/discover-hello?payload=discover-hello')
        .timeout(const Duration(seconds: DISCOVER_TIMEOUT))
        .catchError((e) {
      print(e);
    });
  }

  static fetchNVCN(ScpDevice device) async {
    //plain text = <salt> + ":" + "security-fetch-nvcn" + ":" + <device ID>
    String salt = ScpCrypto().generatePassword();
    String payload = "$salt:security-fetch-nvcn:${device.deviceId}";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";
    return await http
        .get('http://${device.ipAddress}:$PORT/secure-control?$query')
        .timeout(const Duration(seconds: NVCN_TIMEOUT))
        .catchError((e) {
      print(e);
    });
  }

  static sendNewPassword(ScpDevice device) async {
    // get NVCN
    print('Fetching NVCN');
    var nvcnResponse = await fetchNVCN(device);
    if (nvcnResponse == null) {
      return ScpStatus.RESULT_ERROR;
    }
    if (nvcnResponse.statusCode != 200 || nvcnResponse.bodyBytes == 0) {
      return ScpStatus.RESULT_ERROR;
    }
    ScpResponseFetchNvcn parsedNvcnResponse =
        ScpResponseParser.parseNvcnResponse(nvcnResponse);

    String nvcn = parsedNvcnResponse.nvcn;
    // generate new password
    String password = ScpCrypto().generatePassword();
    //send new password
    // <salt> + ":" + "security-pw-change" + ":" + <device ID> + ":" + <NVCN> + ":" + <new password>

    String salt = ScpCrypto().generatePassword();
    String payload =
        "$salt:security-pw-change:${device.deviceId}:$nvcn:$password";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    // await response
    print('Setting new password');
    var newPasswordResponse = await http
        .get('http://${device.ipAddress}:$PORT/secure-control?$query')
        .timeout(const Duration(seconds: NEW_PASSWORD_TIMEOUT))
        .catchError((e) {
      print(e);
    });

    if (newPasswordResponse == null) {
      print('failed to send new password');
      return ScpStatus.RESULT_ERROR;
    }
    if (newPasswordResponse != null && newPasswordResponse.bodyBytes != null) {
      if (newPasswordResponse.statusCode == 200) {
        ScpResponseSetPassword parsedResponse =
            await ScpResponseParser.parseSetPasswordResponse(
                newPasswordResponse, password);
        if (parsedResponse != null) {
          if (parsedResponse.result == "done") {
            print('Successfully set new password.');
            device.knownPassword = password;
            device.currentPasswordNumber =
                int.parse(parsedResponse.currentPasswordNumber);
            device.isDefaultPasswordSet = false;
            print(device.toString());
            return ScpStatus.RESULT_DONE;
          }
        }
      }
    }
    return ScpStatus.RESULT_ERROR;
  }

  static sendWifiConfig(
      ScpDevice device, String ssid, String preSharedKey) async {
    // get NVCN
    print('Fetching NVCN');
    var nvcnResponse = await fetchNVCN(device);
    if (nvcnResponse == null) {
      return ScpStatus.RESULT_ERROR;
    }
    if (nvcnResponse.statusCode != 200 || nvcnResponse.bodyBytes == 0) {
      return ScpStatus.RESULT_ERROR;
    }
    ScpResponseFetchNvcn parsedNvcnResponse =
        ScpResponseParser.parseNvcnResponse(nvcnResponse);

    String nvcn = parsedNvcnResponse.nvcn;

    //send new wifi credentials
    // <salt> + ":" + "security-wifi-config" + ":" + <device ID> + ":" + <NVCN> + ":" + <ssid> + ":" + <pre-shared-key>

    String salt = ScpCrypto().generatePassword();
    String payload =
        "$salt:security-wifi-config:${device.deviceId}:$nvcn:$ssid:$preSharedKey";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    // await response
    print('Setting new wifi credentials');
    var setWifiCredentialsResponse = await http
        .get('http://${device.ipAddress}:$PORT/secure-control?$query')
        .timeout(const Duration(seconds: SET_WIFI_CREDS_TIMEOUT))
        .catchError((e) {
      print('$e');
    });

    if (setWifiCredentialsResponse == null) {
      print('failed to send Wifi credentials');
      return ScpStatus.RESULT_ERROR;
    }
    if (setWifiCredentialsResponse != null &&
        setWifiCredentialsResponse.bodyBytes != null) {
      if (setWifiCredentialsResponse.statusCode == 200) {
        ScpResponseSetWifiConfig parsedResponse =
            await ScpResponseParser.parseSetWifiConfigResponse(
                setWifiCredentialsResponse, device.knownPassword);
        if (parsedResponse != null) {
          if (parsedResponse.result == ScpStatus.RESULT_SUCCESS) {
            print('Successfully set Wifi config, ready for restart.');
            return ScpStatus.RESULT_DONE;
          } else if (parsedResponse.result == ScpStatus.RESULT_ERROR) {
            print('Failed setting Wifi config.');
            return ScpStatus.RESULT_ERROR;
          }
        }
      }
    }
    return ScpStatus.RESULT_ERROR;
  }

  static sendRestart(ScpDevice device) async {
    // get NVCN
    print('Fetching NVCN');
    var nvcnResponse = await fetchNVCN(device);
    if (nvcnResponse == null) {
      return ScpStatus.RESULT_ERROR;
    }
    if (nvcnResponse.statusCode != 200 || nvcnResponse.bodyBytes == 0) {
      return ScpStatus.RESULT_ERROR;
    }
    ScpResponseFetchNvcn parsedNvcnResponse =
        ScpResponseParser.parseNvcnResponse(nvcnResponse);

    String nvcn = parsedNvcnResponse.nvcn;

    //send new wifi credentials
    // <salt> + ":" + "security-wifi-config" + ":" + <device ID> + ":" + <NVCN>

    String salt = ScpCrypto().generatePassword();
    String payload = "$salt:security-restart:${device.deviceId}:$nvcn";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    // await response
    print('Restarting device.');
    var restartDeviceResponse = await http
        .get('http://${device.ipAddress}:$PORT/secure-control?$query')
        .timeout(const Duration(seconds: RESTART_TIMEOUT))
        .catchError((e) {
      print(e);
    });

    if (restartDeviceResponse == null) {
      print('failed to restart device');
      return ScpStatus.RESULT_ERROR;
    }
    if (restartDeviceResponse != null &&
        restartDeviceResponse.bodyBytes != null) {
      if (restartDeviceResponse.statusCode == 200) {
        ScpResponseRestart parsedResponse =
            await ScpResponseParser.parseRestartDeviceResponse(
                restartDeviceResponse, device.knownPassword);
        if (parsedResponse != null) {
          if (parsedResponse.result == ScpStatus.RESULT_SUCCESS) {
            print('Successfully restarted device.');
            return ScpStatus.RESULT_DONE;
          } else if (parsedResponse.result == ScpStatus.RESULT_ERROR) {
            print('failed to restart device');
            return ScpStatus.RESULT_ERROR;
          }
        }
      }
    }
    return ScpStatus.RESULT_ERROR;
  }

  static sendResetToDefault(ScpDevice device) async {
    // get NVCN
    print('Fetching NVCN');
    var nvcnResponse = await fetchNVCN(device);
    if (nvcnResponse == null) {
      return ScpStatus.RESULT_ERROR;
    }
    if (nvcnResponse.statusCode != 200 || nvcnResponse.bodyBytes == 0) {
      return ScpStatus.RESULT_ERROR;
    }
    ScpResponseFetchNvcn parsedNvcnResponse =
        ScpResponseParser.parseNvcnResponse(nvcnResponse);

    String nvcn = parsedNvcnResponse.nvcn;

    //send control command
    // <salt> + ":" + "security-reset-to-default" + ":" + <device ID> + ":" + <NVCN>

    String salt = ScpCrypto().generatePassword();
    String payload = "$salt:security-reset-to-default:${device.deviceId}:$nvcn";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    // await response
    print('Send reset to default message');
    var resetToDefaultMessage = await http
        .get('http://${device.ipAddress}:$PORT/secure-control?$query')
        .timeout(const Duration(seconds: RESET_TO_DEFAULT_TIMEOUT))
        .catchError((e) {
      print(e);
    });

    if (resetToDefaultMessage == null) {
      print('failed to send reset to default message');
      return ScpStatus.RESULT_ERROR;
    }
    if (resetToDefaultMessage != null &&
        resetToDefaultMessage.bodyBytes != null) {
      if (resetToDefaultMessage.statusCode == 200) {
        ScpResponseResetToDefault parsedResponse =
            await ScpResponseParser.parseResetToDefault(
                resetToDefaultMessage, device.knownPassword);
        if (parsedResponse != null) {
          if (parsedResponse.result == ScpStatus.RESULT_SUCCESS) {
            print('Successfully reset the device to default.');
            return ScpStatus.RESULT_SUCCESS;
          } else if (parsedResponse.result == ScpStatus.RESULT_ERROR) {
            print('Failed resetting the device to default.');
            return ScpStatus.RESULT_ERROR;
          }
        }
      } else {
        print('Status code not 200: ${resetToDefaultMessage.statusCode}');
      }
    }
    return ScpStatus.RESULT_ERROR;
  }

  static sendControl(ScpDevice device, String action) async {
    // get NVCN
    print('Fetching NVCN');
    var nvcnResponse = await fetchNVCN(device);
    if (nvcnResponse == null) {
      return ScpStatus.RESULT_ERROR;
    }
    if (nvcnResponse.statusCode != 200 || nvcnResponse.bodyBytes == 0) {
      return ScpStatus.RESULT_ERROR;
    }
    ScpResponseFetchNvcn parsedNvcnResponse =
        ScpResponseParser.parseNvcnResponse(nvcnResponse);

    String nvcn = parsedNvcnResponse.nvcn;

    //send control command
    // <salt> + ":" + "control" + ":" + <device ID> + ":" + <NVCN> + ":" + action

    String salt = ScpCrypto().generatePassword();
    String payload = "$salt:control:${device.deviceId}:$nvcn:$action";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    // await response
    print('Send control command: $action');
    var controlResponse = await http
        .get('http://${device.ipAddress}:$PORT/secure-control?$query')
        .timeout(const Duration(seconds: CONTROL_TIMEOUT))
        .catchError((e) {
      print(e);
    });

    if (controlResponse == null) {
      print('failed to send control command');
      return ScpStatus.RESULT_ERROR;
    }
    if (controlResponse != null && controlResponse.bodyBytes != null) {
      if (controlResponse.statusCode == 200) {
        ScpResponseControl parsedResponse =
            await ScpResponseParser.parseControlResponse(
                controlResponse, device.knownPassword);
        if (parsedResponse != null) {
          if (parsedResponse.result == ScpStatus.RESULT_SUCCESS &&
              action == parsedResponse.action) {
            print('Successfully controlled device.');
            return ScpStatus.RESULT_SUCCESS;
          } else if (parsedResponse.result == ScpStatus.RESULT_ERROR ||
              action != parsedResponse.action) {
            print('Failed controlling device.');
            return ScpStatus.RESULT_ERROR;
          }
        }
      } else {
        print('Status code not 200: ${controlResponse.statusCode}');
      }
    }
    return ScpStatus.RESULT_ERROR;
  }

  static String urlEncode(String s) {
    return Uri.encodeQueryComponent(s);
  }
}
