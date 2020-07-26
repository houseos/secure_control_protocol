import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/util/ip_range.dart';
import 'package:test/test.dart';

void main() async {

  String key = "01234567890123456789012345678901";
  String inputString = "test";

  // ====== Test encryption ======
  await test('Encrypt string "test"', () async {
    ScpJson json = await ScpCrypto().encryptThenEncode(key, inputString);   
    expect();
  });


  // ====== Test decryption ======

  // ====== Combined tests ======

  //Test Octets to Integer conversion
  test('Get integer value of 192.168.2.122', () {
    expect(IPRange.octetsToInteger([192, 168, 2, 122]), equals(3232236154));
  });

  test('Get integer value of 10.226.181.5', () {
    expect(IPRange.octetsToInteger([10, 226, 181, 5]), equals(182629637));
  });


}
