import Flutter
import UIKit
import LocalAuthentication

public class EncryptionUtilPlugin: NSObject, FlutterPlugin {
  private let channelName = "social.julia/encryptionutil"

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: channelName, binaryMessenger: registrar.messenger())
    let instance = EncryptionUtilPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "encrypt":
      guard let args = call.arguments as? [String: String],
            let plaintext = args["plaintext"] else {
        result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments", details: nil))
        return
      }
      encrypt(plaintext: plaintext, result: result)
    case "decrypt":
      guard let args = call.arguments as? [String: String],
            let ciphertext = args["ciphertext"] else {
        result(FlutterError(code: "INVALID_ARGUMENTS", message: "Invalid arguments", details: nil))
        return
      }
      decrypt(ciphertext: ciphertext, result: result)
    case "getPublicKey":
      getPublicKey(result: result)
    case "isEmulator":
      result(isEmulator())
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func encrypt(plaintext: String, result: @escaping FlutterResult) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
      result(FlutterError(code: "UNAVAILABLE", message: "Biometric authentication not available", details: nil))
      return
    }

    let data = Data(plaintext.utf8)
    do {
      let publicKey = try context.secureEnclavePublicKey()
      let encryptedData = try context.encrypt(data, publicKey: publicKey)
      result(encryptedData.base64EncodedString())
    } catch {
      result(FlutterError(code: "ENCRYPTION_FAILED", message: "Encryption failed", details: error.localizedDescription))
    }
  }

  private func decrypt(ciphertext: String, result: @escaping FlutterResult) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
      result(FlutterError(code: "UNAVAILABLE", message: "Biometric authentication not available", details: nil))
      return
    }

    guard let data = Data(base64Encoded: ciphertext) else {
      result(FlutterError(code: "INVALID_CIPHERTEXT", message: "Invalid ciphertext", details: nil))
      return
    }

    do {
      let decryptedData = try context.decrypt(data)
      result(String(decoding: decryptedData, as: UTF8.self))
    } catch {
      result(FlutterError(code: "DECRYPTION_FAILED", message: "Decryption failed", details: error.localizedDescription))
    }
  }

  private func getPublicKey(result: @escaping FlutterResult) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
      result(FlutterError(code: "UNAVAILABLE", message: "Biometric authentication not available", details: nil))
      return
    }

    do {
      let publicKey = try context.secureEnclavePublicKey()
      result(publicKey.base64EncodedString())
    } catch {
      result(FlutterError(code: "KEY_RETRIEVAL_FAILED", message: "Failed to retrieve public key", details: error.localizedDescription))
    }
  }

  private func isEmulator() -> Bool {
    #if targetEnvironment(simulator)
    return true
    #else
    return false
    #endif
  }
}
