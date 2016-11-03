package com.cordova.plugin.android.fingerprintkey;

import android.app.Activity;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;

import java.io.IOException;
import java.security.KeyStore;
import java.security.ProviderException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Created by shepelt on 2016. 9. 21..
 */

public class FingerprintScanner {
    private final Activity activity;
    private final String keyID;
    private FingerprintManagerCompat fm;
    private Locale locale;

    public FingerprintScanner(Activity activity, String keyID) {
        this.keyID = keyID;
        this.activity = activity;
        this.fm = FingerprintManagerCompat.from(activity.getApplicationContext());

        FingerprintScanner.packageName = this.activity.getApplicationContext().getPackageName();
        FingerprintScanner.mDisableBackup = false;
    }

    public boolean isFingerprintAvailable() {
        return fm.isHardwareDetected()
                && fm.hasEnrolledFingerprints();
    }

    public boolean isHardwareDetected() {
        return fm.isHardwareDetected();
    }

    public boolean hasEnrolledFingerprints() {
        return fm.hasEnrolledFingerprints();
    }


    public static String packageName;
    public static boolean mDisableBackup;

    public void generateSeed() throws IOException {
        generateSeed(this.keyID);
    }

    public static void generateSeed(String keyID) throws IOException {
        KeyStore mKeyStore = null;
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);
        } catch (Exception e) {
            throw new IOException("Failed to load keystore", e);
        }

        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGen.init(new KeyGenParameterSpec.Builder(keyID, KeyProperties.PURPOSE_SIGN).setUserAuthenticationRequired(true).build());
            keyGen.generateKey();
        } catch (Exception e) {
            throw new IOException("Failed to create key", e);
        }
    }
    public void removeSeed() throws IOException {
        removeSeed(this.keyID);
    }
    public static void removeSeed(String keyID) throws IOException {
        try {
            KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);
            mKeyStore.deleteEntry(keyID);
        } catch (Exception e) {
            throw new IOException("Failed to remove key", e);
        }
    }

    private Mac initCrypto() throws IOException {
        try {
            KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);

            SecretKey key = (SecretKey) mKeyStore.getKey(keyID, null);
            if (key == null) {
                return null;
            }

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac;
        } catch (ProviderException e) {
            if (e.getCause().getMessage().equals("Key user not authenticated")) {
                throw new IOException("Unahutorized to access keystore", e.getCause());
            } else {
                throw new IOException("Failed to access keystore", e.getCause());
            }
        } catch (android.security.keystore.KeyPermanentlyInvalidatedException e) {
            System.out.println("key invalidated");
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException("Failed to access keystore", e.getCause());
        }
    }

    private byte[] fetchSeed(Mac mac) throws IOException {
        try {
            byte[] hmacData = mac.doFinal(keyID.getBytes("UTF-8"));
            return hmacData;
        } catch (ProviderException e) {
            if (e.getCause().getMessage().equals("Key user not authenticated")) {
                throw new IOException("Unahutorized to access keystore", e.getCause());
            } else {
                throw new IOException("Failed to access keystore", e.getCause());
            }
        } catch (Exception e) {
            throw new IOException("Failed to access keystore", e.getCause());
        }
    }

    public void setLocale(Locale locale) {
        this.locale = locale;
    }

    private static String byteArrayToHex(byte[] ba) {
        if (ba == null || ba.length == 0) {
            return null;
        }

        StringBuffer sb = new StringBuffer(ba.length * 2);
        String hexNumber;
        for (int x = 0; x < ba.length; x++) {
            hexNumber = "0" + Integer.toHexString(0xff & ba[x]);

            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }
        return sb.toString();
    }

    public void startLock(final Callback callback, int waitTime) throws IOException {
        FingerprintAuthenticationLockDialogFragment mFragment = new FingerprintAuthenticationLockDialogFragment();
        mFragment.setLocale(this.locale);
        mFragment.setCallback(new FingerprintAuthenticationLockDialogFragment.Callback() {
            @Override
            public void onSuccess() {
                callback.onSuccess("ok");
            }

            @Override
            public void onError(int errCode) {
                callback.onError(errCode, 0);
            }

            @Override
            public void onCancel() {
                callback.onCancel();
            }
        });
        mFragment.setWaitTime(waitTime);
        mFragment.show(this.activity.getFragmentManager(), "FpAuthDialog");
    }

    public void startScan(final Callback callback) throws IOException {
        final Mac mac = this.initCrypto();
        if (mac == null) {
            callback.onError(-314, 0);
            return;
        }

        FingerprintAuthenticationDialogFragment mFragment = new FingerprintAuthenticationDialogFragment();
        mFragment.setLocale(this.locale);
        mFragment.setCallback(new FingerprintAuthenticationDialogFragment.Callback() {
            @Override
            public void onSuccess() {
                try {
                    callback.onSuccess(byteArrayToHex(fetchSeed(mac)));
                } catch (IOException e) {
                    callback.onError(-1, 0);
                }
            }

            @Override
            public void onError(int errCode, int attempts) {
                callback.onError(errCode, attempts);
            }

            @Override
            public void onCancel() {
                callback.onCancel();
            }
        });
        mFragment.setCryptoObject(new FingerprintManagerCompat.CryptoObject(mac));
        mFragment.show(this.activity.getFragmentManager(), "FpAuthDialog");
}

    public static class Locale {
        public String titleText = "";
        public String cancelText = "";
        public String descText = "";
        public String hintText = "";
        public String notRecognizedText = "";
        public String successText = "";
        public String tooManyTries = "";
    }

    public interface Callback {
        void onSuccess(String privateKey);
        void onError(int errCode, int attempts);
        void onCancel();
    }
}
