/*
 * Copyright (c) 2022 CriticalBlue Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.criticalblue.approov_service_flutter_httpclient;

import android.content.Context;
import android.os.Looper;
import android.os.Handler;

import com.criticalblue.approovsdk.Approov;

import java.net.URL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.HttpsURLConnection;

import androidx.annotation.NonNull;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.StandardMethodCodec;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

// ApproovHttpClientPlugin provides the bridge to the Approov SDK itself. Methods are initiated using the
// MethodChannel to call various methods within the SDK. A facility is also provided to probe the certificates
// presented on any particular URL to implement the pinning. Note that the MethodChannel must run on a background
// thread since it makes blocking calls.
public class ApproovHttpClientPlugin implements FlutterPlugin, MethodCallHandler {
  // CertificatePrefetcher is a Runnable that fetches the certificates for a given URL. This allows the
  // certificates to be fetched on a background thread in parallel with other fetches, and with an Approov
  // token fetch.
  private class CertificateFetcher implements Runnable {
    // Connect timeout (in ms) for host certificate fetch
    private static final int FETCH_CERTIFICATES_TIMEOUT_MS = 3000;

    // Handler to be used to call back on the main thread
    private Handler handler;

    // ID for the transaction
    private final String transactionID;

    // URL being probed for the certificates
    private final URL url;

    /**
     * Constructor for the CertificateFetcher, which sets up ready for ansynchronous
     * execution.
     * 
     * @param handler is the Handler to be used to call back on the main thread
     * @param transactionID is the String ID to be used to identify the transaction
     * @param url The URL to fetch the certificates from.
     */
    public CertificateFetcher(Handler handler, String transactionID, URL url) {
      this.handler = handler;
      this.transactionID = transactionID;
      this.url = url;
    }

    /**
     * Runs to fetch the certificates from the URL and send then back to Dart.
     */
    @Override
    public void run() {
      try {
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(FETCH_CERTIFICATES_TIMEOUT_MS);
        connection.connect();
        Certificate[] certificates = connection.getServerCertificates();
        List<byte[]> hostCertificates = new ArrayList<>();
        for (Certificate certificate: certificates) {
          hostCertificates.add(certificate.getEncoded());
        }
        connection.disconnect();
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("TransactionID", transactionID);
        resultMap.put("Certificates", hostCertificates);
        handler.post(() -> channel.invokeMethod("response", resultMap));
      } catch (Exception e) {
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("TransactionID", transactionID);
        resultMap.put("Exception", e.getLocalizedMessage());
        handler.post(() -> channel.invokeMethod("response", resultMap));
      }
    }
  }

  /**
   * Utility class for providing a callback handler for receiving a token fetch result on an
   * internal asynchronous request. This is for the prefetch case where the actual result is
   * not required.
   */
  private class InternalCallBackHandler implements Approov.TokenFetchCallback {
    // Handler to be used to call back on the main thread
    private Handler handler;

    // handle identfifer for the transaction
    private final String transactionID;

    /**
     * Construct a new internal callback handler.
     * 
     * @param handler is the Handler to be used to call back on the main thread
     * @param transactionID is the String ID to be used to identify the transaction
     */
    InternalCallBackHandler(Handler handler, String transactionID) {
      this.handler = handler;
      this.transactionID = transactionID;
    }

    @Override
    public void approovCallback(Approov.TokenFetchResult tokenFetchResult) {
      Map<String, Object> resultMap = new HashMap<>();
      resultMap.put("TransactionID", transactionID);
      resultMap.put("TokenFetchStatus", tokenFetchResult.getStatus().toString());
      resultMap.put("Token", tokenFetchResult.getToken());
      resultMap.put("SecureString", tokenFetchResult.getSecureString());
      resultMap.put("ARC", tokenFetchResult.getARC());
      resultMap.put("RejectionReasons", tokenFetchResult.getRejectionReasons());
      resultMap.put("IsConfigChanged", tokenFetchResult.isConfigChanged());
      resultMap.put("IsForceApplyPins", tokenFetchResult.isForceApplyPins());
      resultMap.put("MeasurementConfig", tokenFetchResult.getMeasurementConfig());
      resultMap.put("LoggableToken", tokenFetchResult.getLoggableToken());
      handler.post(() -> channel.invokeMethod("response", resultMap));
    }
  }

  // The MethodChannel for the communication between Flutter and native Android
  //
  // This local reference serves to register the plugin with the Flutter Engine and unregister it
  // when the Flutter Engine is detached from the Activity
  private MethodChannel channel;

  // Application context passed to Approov initialization
  private static Context appContext;

  // Provides any prior initial configuration supplied, to allow a reinitialization caused by
  // a hot restart if the configuration is the same
  private static String initializedConfig;

  // Handler for the main thread to allow call backs since they must be in the context of that thread
  private Handler handler;

  // Next transaction ID to be used for asynchronous operations
  private static int nextID;

  @Override
  public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
    BinaryMessenger messenger = flutterPluginBinding.getBinaryMessenger();
    channel = new MethodChannel(messenger, "approov_service_flutter_httpclient");
    channel.setMethodCallHandler(this);
    appContext = flutterPluginBinding.getApplicationContext();
    handler = new Handler(Looper.getMainLooper());
  }

  /**
   * Gets the next unique transaction ID to be used for asynchronous operations.
   * 
   * @return the next transaction ID to be used
   */
  private String getNextID() {
    return Integer.toString(nextID++);
  }

  @Override
  public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
    if (call.method.equals("initialize")) {
      String initialConfig = call.argument("initialConfig");
      String commentString = call.argument("comment");
      if ((initializedConfig == null) || !initializedConfig.equals(initialConfig) || (commentString != null)) {
        // only actually initialize if we haven't before, if there is a change in the
        // configuration provided or we have a comment to add to the initialization
        try {
          Approov.initialize(appContext, initialConfig, call.argument("updateConfig"), call.argument("comment"));
          initializedConfig = initialConfig;
          result.success(null);
        } catch(Exception e) {
          result.error("Approov.initialize", e.getLocalizedMessage(), null);
        }
      } else {
        // the previous initialization is compatible
        result.success(null);
      }
    } else if (call.method.equals("fetchConfig")) {
      try {
        result.success(Approov.fetchConfig());
      } catch(Exception e) {
        result.error("Approov.fetchConfig", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("getDeviceID")) {
      try {
        result.success(Approov.getDeviceID());
      } catch(Exception e) {
        result.error("Approov.getDeviceID", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("getPins")) {
      try {
        result.success(Approov.getPins((String) call.argument("pinType")));
      } catch(Exception e) {
        result.error("Approov.getPins", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("setDataHashInToken")) {
      try {
        Approov.setDataHashInToken((String) call.argument("data"));
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.setDataHashInToken", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("setDevKey")) {
      try {
        Approov.setDevKey((String) call.argument("devKey"));
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.setDevKey", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("getMessageSignature")) {
      try {
        String messageSignature = Approov.getMessageSignature((String) call.argument("message"));
        result.success(messageSignature);
      } catch(Exception e) {
        result.error("Approov.getMessageSignature", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("setUserProperty")) {
      try {
        Approov.setUserProperty(call.argument("property"));
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.setUserProperty", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchHostCertificates")) {
      try {
        final URL url = new URL(call.argument("url"));
        String aID = getNextID();
        CertificateFetcher certFetcher = new CertificateFetcher(handler, aID, url);
        new Thread(certFetcher).start();
        result.success(aID);
      } catch(Exception e) {
        result.error("Approov.fetchHostCertificates", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchApproovToken")) {
      try {
        String aID = getNextID();
        InternalCallBackHandler aCallBackHandler = new InternalCallBackHandler(handler, aID);
        Approov.fetchApproovToken(aCallBackHandler, call.argument("url"));
        result.success(aID);
      } catch(Exception e) {
        result.error("Approov.fetchApproovToken", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchSecureString")) {
      try {
        String aID = getNextID();
        InternalCallBackHandler aCallBackHandler = new InternalCallBackHandler(handler, aID);
        Approov.fetchSecureString(aCallBackHandler, call.argument("key"), call.argument("newDef"));
        result.success(aID);
      } catch(Exception e) {
        result.error("Approov.fetchSecureString", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchCustomJWT")) {
      try {
        String aID = getNextID();
        InternalCallBackHandler aCallBackHandler = new InternalCallBackHandler(handler, aID);
        Approov.fetchCustomJWT(aCallBackHandler, call.argument("payload"));
        result.success(aID);
      } catch(Exception e) {
        result.error("Approov.fetchCustomJWT", e.getLocalizedMessage(), null);
      }
    } else {
      result.notImplemented();
    }
  }

  @Override
  public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
    channel.setMethodCallHandler(null);
  }
}
