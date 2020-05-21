import 'dart:ffi';

import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';
import 'package:secure_control_protocol/scp_response_parser.dart';

class ScpMessageSender {
  static sendDiscoverHello(String ip) async {
    return await http
        .get('http://$ip/secure-control/discover-hello?payload=discover-hello')
        .timeout(const Duration(seconds: 1))
        .catchError((e) {});
  }

  static fetchNVCN(ScpDevice device) async {
   return await http
        .get('http://${device.ipAddress}/secure-control/security-fetch-nvcn')
        .timeout(const Duration(seconds: 1))
        .catchError((e) {});
  }

  static sendNewPassword(ScpDevice device) async{
    // get NVCN
    print('Fetching NVCN');
    var response = await fetchNVCN(device);
    if (response == null){
      return null;
    } 
    if (response.statusCode != 200  || response.bodyBytes == 0) {
      return null;
    } 
    ScpResponseFetchNvcn parsedResponse =
                ScpResponseParser.parseNvcnResponse(response);

    String nvcn = parsedResponse.nvcn;
    // generate new password
    String password = ScpCrypto().generatePassword();
    //send new password
    // NVCN:deviceID:security-pw-change:newpassword
    String payload = "$nvcn:${device.deviceId}:security-pw-change:$password";
    ScpJson scpJson = await ScpCrypto().encryptThenEncode(device.knownPassword, payload);
    device.knownPassword = password;
    
    String query = "nonce=${urlEncode(scpJson.encryptedPayload.base64Nonce)}";
    query += "&payload=${urlEncode(scpJson.encryptedPayload.base64Data)}";
    query += "&payloadLength=${scpJson.encryptedPayload.dataLength}";
    query += "&mac=${urlEncode(scpJson.encryptedPayload.base64Mac)}";

    
    return await http
        .get('http://${device.ipAddress}/secure-control?$query')
        .timeout(const Duration(seconds: 3))
        .catchError((e) {});
  }

  static sendWifiConfig(ScpDevice device, String ssid, String password){
    
      // get NVCN

      //send new password
  }

  static sendRestart(ScpDevice device){

  }

  static sendControlUp(ScpDevice device) {}

  static sendControlDown(ScpDevice device) {}

  static sendControlStop(ScpDevice device) {}

  static String urlEncode(String s) {
  return Uri.encodeQueryComponent(s);
  }
}


