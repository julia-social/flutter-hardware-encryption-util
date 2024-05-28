package social.julia.encryptionutil;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class EncryptionUtilPlugin implements FlutterPlugin, MethodCallHandler {
    private static final String CHANNEL = "social.julia/encryptionutil";
    private static final String KEY_ALIAS = "encryptionKey";
    private MethodChannel channel;

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding binding) {
        channel = new MethodChannel(binding.getBinaryMessenger(), CHANNEL);
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onMethodCall(MethodCall call, Result result) {
        switch (call.method) {
            case "encrypt":
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    String plaintext = call.argument("plaintext");
                    result.success(encrypt(plaintext));
                } else {
                    result.error("UNSUPPORTED_SDK", "Unsupported SDK version", null);
                }
                break;
            case "decrypt":
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    String ciphertext = call.argument("ciphertext");
                    result.success(decrypt(ciphertext));
                } else {
                    result.error("UNSUPPORTED_SDK", "Unsupported SDK version", null);
                }
                break;
            case "getPublicKey":
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    result.success(getPublicKey());
                } else {
                    result.error("UNSUPPORTED_SDK", "Unsupported SDK version", null);
                }
                break;
            case "isEmulator":
                result.success(isEmulator());
                break;
            default:
                result.notImplemented();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
            byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private String getPublicKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setUserAuthenticationRequired(true)
                        .setIsStrongBoxBacked(isHardwareBackedKeystore())
                        .build());
                keyPairGenerator.generateKeyPair();
            }
            PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
            return Base64.getEncoder().encodeToString(publicKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean isHardwareBackedKeystore() {
        return Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("Emulator") || Build.BRAND.startsWith("generic") || Build.DEVICE.startsWith("generic");
    }

    private boolean isEmulator() {
        return Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("Emulator") || Build.BRAND.startsWith("generic") || Build.DEVICE.startsWith("generic");
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
    }
}
