import 'package:flutter/services.dart';
import 'package:platform/platform.dart';

/// Utility class for encrypting and decrypting string data
class EncryptionUtil {
  static const MethodChannel _channel = MethodChannel('social.julia/encryptionutil');
  static const LocalPlatform _localPlatform = LocalPlatform();

  /// Encrypts the given plaintext string
  static Future<String> encrypt(String plaintext) async {
    if (await _isEmulator()) {
      return plaintext; // Skip encryption on emulator
    }

    if (_localPlatform.isIOS) {
      return await _channel.invokeMethod('encrypt', {'plaintext': plaintext});
    } else if (_localPlatform.isAndroid) {
      return await _channel.invokeMethod('encrypt', {'plaintext': plaintext});
    } else {
      throw UnsupportedError('Unsupported platform');
    }
  }

  /// Decrypts the given ciphertext string
  static Future<String> decrypt(String ciphertext) async {
    if (await _isEmulator()) {
      return ciphertext; // Skip decryption on emulator
    }

    if (_localPlatform.isIOS) {
      return await _channel.invokeMethod('decrypt', {'ciphertext': ciphertext});
    } else if (_localPlatform.isAndroid) {
      return await _channel.invokeMethod('decrypt', {'ciphertext': ciphertext});
    } else {
      throw UnsupportedError('Unsupported platform');
    }
  }

  /// Extracts the P256 public key
  static Future<String> getPublicKey() async {
    if (await _isEmulator()) {
      return ''; // Return empty string on emulator
    }

    if (_localPlatform.isIOS) {
      return await _channel.invokeMethod('getPublicKey');
    } else if (_localPlatform.isAndroid) {
      return await _channel.invokeMethod('getPublicKey');
    } else {
      throw UnsupportedError('Unsupported platform');
    }
  }

  /// Checks if the app is running on an emulator
  static Future<bool> _isEmulator() async {
    if (_localPlatform.isIOS) {
      return await _channel.invokeMethod('isEmulator');
    } else if (_localPlatform.isAndroid) {
      return await _channel.invokeMethod('isEmulator');
    } else {
      return false;
    }
  }
}
