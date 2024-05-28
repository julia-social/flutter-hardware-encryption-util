# Flutter-Mobile-Encryption-Util

`EncryptionUtil` is a Flutter plugin for encrypting and decrypting data using secure elements. It leverages the secure enclave on iOS and the Android Keystore system on Android devices to perform secure cryptographic operations. Additionally, it provides functionality to retrieve the device's public key and detect if the app is running on an emulator.

## Features

- **Encrypt and Decrypt Data**: Encrypt and decrypt data securely using platform-specific secure elements.
- **Public Key Retrieval**: Retrieve the device's public key for secure operations.
- **Emulator Detection**: Detect if the app is running on an emulator and skip encryption/decryption operations.

## Installation

Add the following dependency to your `pubspec.yaml` file:

```yaml
dependencies:
  encryption_util:
    git:
      url: git@github.com:julia-social/flutter-hardware-encryption-util.git
      ref: main
```

## Usage

Import the package in your Dart code:

```dart
import 'package:encryption_util/encryption_util.dart';
```

### Encrypt Data

```dart
String plaintext = "Hello, World!";
String encryptedText = await EncryptionUtil.encrypt(plaintext);
print("Encrypted Text: $encryptedText");
```

### Decrypt Data

```dart
String ciphertext = "EncryptedTextHere";
String decryptedText = await EncryptionUtil.decrypt(ciphertext);
print("Decrypted Text: $decryptedText");
```

### Retrieve Public Key

```dart
String publicKey = await EncryptionUtil.getPublicKey();
print("Public Key: $publicKey");
```

### Check if Running on Emulator

```dart
bool isEmulator = await EncryptionUtil.isEmulator();
print("Is Emulator: $isEmulator");
```

## Platform-Specific Setup

### iOS

Ensure you have the following in your `ios/Podfile`:

```ruby
platform :ios, '10.0'

post_install do |installer|
  installer.pods_project.targets.each do |target|
    flutter_additional_ios_build_settings(target)
  end
end
```

Add the following entries to your `Info.plist` file:

```xml
<key>NSFaceIDUsageDescription</key>
<string>We use Face ID to secure your data.</string>
<key>NSBiometricUsageDescription</key>
<string>We use biometric authentication to secure your data.</string>
```

### Android

Ensure your `android/app/build.gradle` contains:

```groovy
android {
    ...
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
    ...
}
```

Add the following permissions to your `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

