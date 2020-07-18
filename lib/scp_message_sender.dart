import 'dart:ffi';

import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';
import 'package:secure_control_protocol/scp_response_parser.dart';
import 'package:secure_control_protocol/scp_status.dart';

class ScpMessageSender {
  static sendDiscoverHello(String ip) async {
    return await http
        .get('http://$ip/secure-control/discover-hello?payload=discover-hello')
        .timeout(const Duration(seconds: 3))
        .catchError((e) {});
  }

  static fetchNVCN(ScpDevice device) async {
    //plain text = <salt> + ":" + "security-fetch-nvcn" + ":" + <device ID>
    String salt = "1";
    String payload = "$salt:security-fetch-nvcn:${device.deviceId}";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";
    return await http
        .get('http://${device.ipAddress}/secure-control?$query')
        .timeout(const Duration(seconds: 3))
        .catchError((e) {});
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
    // NVCN:deviceID:security-pw-change:newpassword
    String salt = "1";
    String payload =
        "$salt:security-pw-change:${device.deviceId}:$nvcn:$password";
    ScpJson scpJson =
        await ScpCrypto().encryptThenEncode(device.knownPassword, payload);

    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    // await response
    var newPasswordResponse = await http
        .get('http://${device.ipAddress}/secure-control?$query')
        .timeout(const Duration(seconds: 3))
        .catchError((e) {});

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
            print(device.toString());
            return ScpStatus.RESULT_DONE;
          }
        }
      }
    }
    return ScpStatus.RESULT_ERROR;
  }

  static sendWifiConfig(ScpDevice device, String ssid, String password) {
    // get NVCN

    //send new password
  }

  static sendRestart(ScpDevice device) {}

  static sendControl(ScpDevice device, String action) {}

  static String urlEncode(String s) {
    return Uri.encodeQueryComponent(s);
  }
}
