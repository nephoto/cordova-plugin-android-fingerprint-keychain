package com.cordova.plugin.android.fingerprintkey;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@TargetApi(7)
public class FingerprintKey extends CordovaPlugin {

    public static final String TAG = "FingerprintKey";

    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;

    /**
     * Constructor.
     */
    public FingerprintKey() {
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "Init FingerprintAuth");
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);

        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArry of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action,
                           JSONArray args,
                           CallbackContext callbackContext) throws JSONException {
        mCallbackContext = callbackContext;
        Log.v(TAG, "FingerprintAuth action: " + action);
        final JSONObject arg_object = args.getJSONObject(0);

        if (action.equals("lock")) {
            FingerprintScanner scanner = new FingerprintScanner(cordova.getActivity(), null);
                try {
                    // try to register
                    FingerprintScanner.Locale locale = new FingerprintScanner.Locale();
                    if (arg_object.has("locale")) {
                        locale.descText = arg_object.getJSONObject("locale").getString("desc");//"설명";
                        locale.titleText = arg_object.getJSONObject("locale").getString("title");//"타이틀";
                        locale.cancelText = arg_object.getJSONObject("locale").getString("cancel");//"타이틀";
                    } else {
                        locale.descText = "설명";
                        locale.titleText = "타이틀";
                        locale.cancelText = "취소";
                    }
                    scanner.setLocale(locale);
                    int waitTime = arg_object.getJSONObject("locale").getInt("locktime");

                    scanner.startLock(new FingerprintScanner.Callback() {
                        @Override
                        public void onSuccess(String privateKey) {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "ok");
                                resultJson.put("key", privateKey);
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        @Override
                        public void onError(int errCode, int attempts) {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "error");
                                resultJson.put("error", errCode);
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        @Override
                        public void onCancel() {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "cancelled");
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }, waitTime);
                } catch (IOException e) {   
                    e.printStackTrace();
                    JSONObject resultJson = new JSONObject();
                    resultJson.put("status", "error");
                    resultJson.put("error", "Failed to generate key");
                    mPluginResult = new PluginResult(PluginResult.Status.OK);
                    mCallbackContext.success(resultJson);
                    mCallbackContext.sendPluginResult(mPluginResult); 
                }
            return true;
        } else if (action.equals("initkey")) {
            if (!arg_object.has("keyId")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }
            FingerprintScanner scanner = new FingerprintScanner(cordova.getActivity(), arg_object.getString("keyId"));

            if (scanner.isFingerprintAvailable()) {
                try {
                    scanner.generateSeed();
                    
                    // try to register
                    FingerprintScanner.Locale locale = new FingerprintScanner.Locale();
                    if (arg_object.has("locale")) {
                        locale.descText = arg_object.getJSONObject("locale").getString("desc");//"설명";
                        locale.cancelText = arg_object.getJSONObject("locale").getString("cancel");//"취소";
                        locale.titleText = arg_object.getJSONObject("locale").getString("title");//"타이틀";
                        locale.hintText = arg_object.getJSONObject("locale").getString("hint");//"지문";
                        locale.successText = arg_object.getJSONObject("locale").getString("success");//"인식성공";
                        locale.notRecognizedText = arg_object.getJSONObject("locale").getString("notrecognized");//"인식실패";
                        locale.tooManyTries = arg_object.getJSONObject("locale").getString("toomanytries");//"인식실패";
                    } else {
                        locale.descText = "설명";
                        locale.cancelText = "취소";
                        locale.titleText = "타이틀";
                        locale.hintText = "지문";
                        locale.successText = "인식성공";
                        locale.notRecognizedText = "인식실패";
                        locale.tooManyTries = "연속으로 지문 인증을 실패하였습니다. 잠시 후 다시 이용해 주시기 바랍니다";
                    }
                    scanner.setLocale(locale);

                    scanner.startScan(new FingerprintScanner.Callback() {
                        @Override
                        public void onSuccess(String privateKey) {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "ok");
                                resultJson.put("key", privateKey);
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        @Override
                        public void onError(int errCode, int attempts) {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "error");
                                resultJson.put("error", errCode);
                                resultJson.put("attempts", attempts);
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        @Override
                        public void onCancel() {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "cancelled");
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                } catch (IOException e) {   
                    JSONObject resultJson = new JSONObject();
                    resultJson.put("status", "error");
                    resultJson.put("error", "Failed to generate key");
                    mPluginResult = new PluginResult(PluginResult.Status.OK);
                    mCallbackContext.success(resultJson);
                    mCallbackContext.sendPluginResult(mPluginResult); 
                }
            } else {
                JSONObject resultJson = new JSONObject();
                resultJson.put("status", "error");
                resultJson.put("error", "Fingerprint authentication not available");
                mPluginResult = new PluginResult(PluginResult.Status.OK);
                mCallbackContext.success(resultJson);
                mCallbackContext.sendPluginResult(mPluginResult);
            }
            return true;


        } else if (action.equals("fetchkey")) {

            if (!arg_object.has("keyId")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }
            FingerprintScanner scanner = new FingerprintScanner(cordova.getActivity(), arg_object.getString("keyId"));

            if (scanner.isFingerprintAvailable()) {
                try {
                    // try to register
                    FingerprintScanner.Locale locale = new FingerprintScanner.Locale();
                    if (arg_object.has("locale")) {
                        locale.descText = arg_object.getJSONObject("locale").getString("desc");//"설명";
                        locale.cancelText = arg_object.getJSONObject("locale").getString("cancel");//"취소";
                        locale.titleText = arg_object.getJSONObject("locale").getString("title");//"타이틀";
                        locale.hintText = arg_object.getJSONObject("locale").getString("hint");//"지문";
                        locale.successText = arg_object.getJSONObject("locale").getString("success");//"인식성공";
                        locale.notRecognizedText = arg_object.getJSONObject("locale").getString("notrecognized");//"인식실패";
                        locale.tooManyTries = arg_object.getJSONObject("locale").getString("toomanytries");//"인식실패";
                    } else {
                        locale.descText = "설명";
                        locale.cancelText = "취소";
                        locale.titleText = "타이틀";
                        locale.hintText = "지문";
                        locale.successText = "인식성공";
                        locale.notRecognizedText = "인식실패";
                        locale.tooManyTries = "연속으로 지문 인증을 실패하였습니다. 잠시 후 다시 이용해 주시기 바랍니다";
                    }
                    scanner.setLocale(locale);

                    scanner.startScan(new FingerprintScanner.Callback() {
                        @Override
                        public void onSuccess(String privateKey) {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "ok");
                                resultJson.put("key", privateKey);
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        @Override
                        public void onError(int errCode, int attempts) {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "error");
                                resultJson.put("error", errCode);
                                resultJson.put("attempts", attempts);
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        @Override
                        public void onCancel() {
                            try {
                                JSONObject resultJson = new JSONObject();
                                resultJson.put("status", "cancelled");
                                mPluginResult = new PluginResult(PluginResult.Status.OK);
                                mCallbackContext.success(resultJson);
                                mCallbackContext.sendPluginResult(mPluginResult);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                } catch (IOException e) {   
                    JSONObject resultJson = new JSONObject();
                    resultJson.put("status", "error");
                    resultJson.put("error", "Failed to generate key");
                    mPluginResult = new PluginResult(PluginResult.Status.OK);
                    mCallbackContext.success(resultJson);
                    mCallbackContext.sendPluginResult(mPluginResult); 
                }
            } else {
                JSONObject resultJson = new JSONObject();
                resultJson.put("status", "error");
                resultJson.put("error", "Fingerprint authentication not available");
                mPluginResult = new PluginResult(PluginResult.Status.OK);
                mCallbackContext.success(resultJson);
                mCallbackContext.sendPluginResult(mPluginResult);
            }
            return true;
        } else if (action.equals("availability")) {
            try {
                FingerprintScanner scanner = new FingerprintScanner(cordova.getActivity(), null);
                JSONObject resultJson = new JSONObject();
                resultJson.put("isAvailable", scanner.isFingerprintAvailable());
                resultJson.put("isHardwareDetected", scanner.isHardwareDetected());
                resultJson.put("hasEnrolledFingerprints", scanner.hasEnrolledFingerprints());
                mPluginResult = new PluginResult(PluginResult.Status.OK);
                mCallbackContext.success(resultJson);
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            } catch (Exception e) {
                JSONObject resultJson = new JSONObject();
                resultJson.put("isAvailable", false);
                resultJson.put("isHardwareDetected", false);
                resultJson.put("hasEnrolledFingerprints", false);
                mPluginResult = new PluginResult(PluginResult.Status.OK);
                mCallbackContext.success(resultJson);
                mCallbackContext.sendPluginResult(mPluginResult);
            return true;
            }
        }
        return false;
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }
}