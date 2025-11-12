/*
 * Copyright (c) 2022-2025 Approov Ltd.
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
import android.util.Log;

import com.criticalblue.approovsdk.Approov;

import java.net.URL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
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
// presented on any particular URL to implement the pinning.
public class ApproovHttpClientPlugin implements FlutterPlugin, MethodCallHandler {
  // CertificatesFetcher is a Runnable that fetches the certificates for a given URL. This allows the
  // certificates to be fetched on a background thread in parallel with other fetches, and with an Approov
  // token fetch.
  private class CertificatesFetcher implements Runnable {
    // Connect timeout (in ms) for host certificate fetch
    private static final int FETCH_CERTIFICATES_TIMEOUT_MS = 3000;

    // Handler to be used to call back on the main thread, or null if not required
    private Handler handler;

    // ID for the transaction
    private final String transactionID;

    // URL being probed for the certificates
    private final URL url;

    // Map to hold the result of the certificates fetch
    private Map<String, Object> resultMap;

    // Latch to indicate when the certificates have been fetched
    private CountDownLatch countDownLatch;

    /**
     * Constructor for the CertificatesFetcher, which sets up ready for asnynchronous
     * execution.
     * 
     * @param handler is the Handler to be used to call back on the main thread, or null if not required
     * @param transactionID is the String ID to be used to identify the transaction
     * @param url The URL to fetch the certificates from
     */
    public CertificatesFetcher(Handler handler, String transactionID, URL url) {
      this.handler = handler;
      this.transactionID = transactionID;
      this.url = url;
      this.resultMap = new HashMap<>();
      this.countDownLatch = new CountDownLatch(1);
    }

    /**
     * Runs to fetch the certificates from the URL and either send then back to Dart via a
     * callback or hold them in a result map to be waited upon.
     */
    @Override
    public void run() {
      try {
        // create the connection
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(FETCH_CERTIFICATES_TIMEOUT_MS);
        connection.connect();

        // fetch the certificates and disconnect
        Certificate[] certificates = connection.getServerCertificates();
        List<byte[]> hostCertificates = new ArrayList<>();
        for (Certificate certificate: certificates) {
          hostCertificates.add(certificate.getEncoded());
        }
        connection.disconnect();

        // send the certificates back to the Flutter Dart layer using the handler to
        // ensure it is done on the main thread
        resultMap.put("TransactionID", transactionID);
        resultMap.put("Certificates", hostCertificates);
        if (handler != null)
          handler.post(() -> fgChannel.invokeMethod("response", resultMap));
      } catch (Exception e) {
        // send any exception back to the Flutter Dart layer using the handler to
        // ensure it is done on the main thread
        resultMap.put("TransactionID", transactionID);
        resultMap.put("Error", e.getLocalizedMessage());
        if (handler != null)
          handler.post(() -> fgChannel.invokeMethod("response", resultMap));
      } finally {
        countDownLatch.countDown();
      }
    }

    /**
     * Get the result from the certificate fetch, waiting if the result is not yet available.
     *
     * @return result map provided after connection, or null if interrupted
     */
    Map<String, Object> getResult() {
      try {
        countDownLatch.await();
      } catch (InterruptedException e) {
        return null;
      }
      return resultMap;
    }
  }

  /**
   * Utility class for providing a callback handler for receiving an Approov fetch result on an
   * internal asynchronous request.
   */
  private class InternalCallBackHandler implements Approov.TokenFetchCallback {
    // Handler to be used to call back on the main thread, or null if no call back neeeded
    private Handler handler;

    // ID for the transaction
    private final String transactionID;

    // Map to hold the result of the Approov fetch
    private Map<String, Object> resultMap;

    // Latch to indicate when the callback has occurred
    private CountDownLatch countDownLatch;

    /**
     * Construct a new internal callback handler.
     * 
     * @param handler is the Handler to be used to call back on the main thread
     * @param transactionID is the String ID to be used to identify the transaction
     */
    InternalCallBackHandler(Handler handler, String transactionID) {
      this.handler = handler;
      this.transactionID = transactionID;
      this.resultMap = new HashMap<>();
      this.countDownLatch = new CountDownLatch(1);
    }

     /**
     * Gets the results from the Approov SDK and sends them back to Dart directly via a callback
     * handler or makes them available as a result to be waited upon.
     */
    @Override
    public void approovCallback(Approov.TokenFetchResult tokenFetchResult) {
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
      resultMap.put("ConfigEpoch", configEpoch);
      countDownLatch.countDown();
      if (handler != null)
        handler.post(() -> fgChannel.invokeMethod("response", resultMap));
    }

    /**
     * Get the result from the Approov fetch, waiting if the result is not yet available.
     *
     * @return result map provided to the callback method, or null if interrupted
     */
    Map<String, Object> getResult() {
      try {
        countDownLatch.await();
      } catch (InterruptedException e) {
        return null;
      }
      return resultMap;
    }
  }

  // The MethodChannel for the foreground communication between Flutter and native Android. This local reference serves
  // to register the plugin with the Flutter Engine and unregister it when the Flutter Engine is detached from
  // the Activity.
  private MethodChannel fgChannel = null;

  // The MethodChannel for background isolate communication between Flutter and native Android. This is used for making calls
  // where there may be some blocking and we wish to prevent this form blocking the isolate completely. This local
  // reference serves to register the plugin with the Flutter Engine and unregister it when the Flutter Engine is detached
  // from the Activity.
  private MethodChannel bgChannel = null;

  // Application context passed to Approov initialization
  private Context appContext;

  // Provides any prior initial configuration supplied, to allow a reinitialization caused by
  // a hot restart if the configuration is the same, or null if not initialized
  private String initializedConfig = null;

  // Provides any prior initial comment supplied, or empty string if none was provided
  private String initializedComment;

  // Counter for the configuration epoch that is incremented whenever the configuration is fetched. This keeps
  // track of dynamic configuration changes and the state is held in the platform layer as we want this to work
  // across multiple different isolates which have independent Dart level state.
  private int configEpoch = 0;

  // Handler for the main thread to allow call backs since they must be in the context of that thread
  private Handler handler;

  // Active set of callback handlers to the Approov SDK - a concurrent map is used since this could be
  // accessed from multiple threads
  private Map<String, InternalCallBackHandler> activeCallBackHandlers;

  // Active set of certificate fetches - a concurrent map is used since this could be accessed from
  // multiple threads
  private Map<String, CertificatesFetcher> activeCertFetches;

  @Override
  public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
    BinaryMessenger rootMessenger = flutterPluginBinding.getBinaryMessenger();
    fgChannel = new MethodChannel(rootMessenger, "approov_service_flutter_httpclient_fg");
    fgChannel.setMethodCallHandler(this);
    BinaryMessenger backgroundMessenger = flutterPluginBinding.getBinaryMessenger();
    bgChannel = new MethodChannel(backgroundMessenger, "approov_service_flutter_httpclient_bg",
            StandardMethodCodec.INSTANCE, backgroundMessenger.makeBackgroundTaskQueue());
    bgChannel.setMethodCallHandler(this);
    appContext = flutterPluginBinding.getApplicationContext();
    handler = new Handler(Looper.getMainLooper());
    activeCallBackHandlers = new ConcurrentHashMap<String, InternalCallBackHandler>();
    activeCertFetches = new ConcurrentHashMap<String, CertificatesFetcher>();
  }

  @Override
  public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
    bgChannel.setMethodCallHandler(null);
    fgChannel.setMethodCallHandler(null);
  }
  
  @Override
  public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
    if (call.method.equals("initialize")) {
      // get the initialization arguments
      String initialConfig = call.argument("initialConfig");
      String commentString = call.argument("comment");
      if (commentString == null) {
        commentString = "";
      }

      // determine if the initialization is needed (indicated by a change in either the initial config string or the comment) -
      // this is necessary because hot restarts or the creation of new isolates means that the Dart level may not have determined
      // that the SDK is already initialized whereas this native layer holds its state
      if ((initializedConfig == null) || !initializedConfig.equals(initialConfig) || !initializedComment.equals(commentString)) {
        // this is a new config or a reinitialization
        try {
          Approov.initialize(appContext, initialConfig, call.argument("updateConfig"), commentString);
        } catch (IllegalStateException e) {
          // log and ignore the error if the SDK is already initialized - this can happen if an app is using multiple
          // different isolates and the initialization was made by a different quickstart (note we don't currently check
          // for the compatibility of the SDK parameters but a future version of the SDK will do this to avoid needing to
          // catch this at all)
          Log.w("ApproovService", "Ignoring initialization error in Approov SDK: " + e.getLocalizedMessage());
        } catch(Exception e) {
            result.error("Approov.initialize", e.getLocalizedMessage(), null);
            return;
        }
        initializedConfig = initialConfig;
        initializedComment = commentString;
        result.success(null);
      } else {
        // the previous initialization is compatible
        result.success(null);
      }
    } else if (call.method.equals("fetchConfig")) {
      try {
        configEpoch++;
        result.success(Approov.fetchConfig());
      } catch(Exception e) {
        result.error("Approov.fetchConfig", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("getConfigEpoch")) {
        result.success(configEpoch);
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
    } else if (call.method.equals("getAccountMessageSignature")) {
      try {
        String messageSignature = Approov.getAccountMessageSignature((String) call.argument("message"));
        result.success(messageSignature);
      } catch (NoSuchMethodError e) {
        try {
          String messageSignature = Approov.getMessageSignature((String) call.argument("message"));
          result.success(messageSignature);
        } catch(Exception inner) {
          result.error("Approov.getAccountMessageSignature", inner.getLocalizedMessage(), null);
        }
      } catch(Exception e) {
        result.error("Approov.getAccountMessageSignature", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("getInstallMessageSignature")) {
      try {
        String messageSignature = Approov.getInstallMessageSignature((String) call.argument("message"));
        result.success(messageSignature);
      } catch(Exception e) {
        result.error("Approov.getInstallMessageSignature", e.getLocalizedMessage(), null);
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
        final String transactionID = call.argument("transactionID");
        final URL url = new URL(call.argument("url"));
        final Boolean performCallBack = call.argument("performCallBack").equals("YES");
        CertificatesFetcher certFetcher = new CertificatesFetcher(performCallBack ? handler : null,
          transactionID, url);
        if (!performCallBack)
          activeCertFetches.put(transactionID, certFetcher);
        new Thread(certFetcher).start();
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.fetchHostCertificates", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("waitForHostCertificates")) {
      String transactionID = call.argument("transactionID");
      CertificatesFetcher certFetcher = activeCertFetches.get(transactionID);
      if (certFetcher != null) {
        Map<String, Object> fetchResult = certFetcher.getResult();
        if (fetchResult != null) {
          activeCertFetches.remove(transactionID);
          result.success(fetchResult);
        } else {
          result.error("Approov.waitForHostCertificates", "Certificate fetch interrupted", null);
        }
      } else {
        result.error("Approov.waitForHostCertificates", "No fetch in progress", null);
      }
    } else if (call.method.equals("fetchApproovToken")) {
      try {
        final String transactionID = call.argument("transactionID");
        final Boolean performCallBack = call.argument("performCallBack").equals("YES");
        InternalCallBackHandler callBackHandler = new InternalCallBackHandler(performCallBack ? handler : null, transactionID);
        Approov.fetchApproovToken(callBackHandler, call.argument("url"));
        if (!performCallBack)
          activeCallBackHandlers.put(transactionID, callBackHandler);
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.fetchApproovToken", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchSecureString")) {
      try {
        final String transactionID = call.argument("transactionID");
        final Boolean performCallBack = call.argument("performCallBack").equals("YES");
        InternalCallBackHandler callBackHandler = new InternalCallBackHandler(performCallBack ? handler : null, transactionID);
        Approov.fetchSecureString(callBackHandler, call.argument("key"), call.argument("newDef"));
        if (!performCallBack)
          activeCallBackHandlers.put(transactionID, callBackHandler);
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.fetchSecureString", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchCustomJWT")) {
      try {
        final String transactionID = call.argument("transactionID");
        final Boolean performCallBack = call.argument("performCallBack").equals("YES");
        InternalCallBackHandler callBackHandler = new InternalCallBackHandler(performCallBack ? handler : null, transactionID);
        Approov.fetchCustomJWT(callBackHandler, call.argument("payload"));
        if (!performCallBack)
          activeCallBackHandlers.put(transactionID, callBackHandler);
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.fetchCustomJWT", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("waitForFetchValue")) {
      String transactionID = call.argument("transactionID");
      InternalCallBackHandler callBackHandler = activeCallBackHandlers.get(transactionID);
      if (callBackHandler != null) {
        Map<String, Object> fetchResult = callBackHandler.getResult();
        if (fetchResult != null) {
          activeCallBackHandlers.remove(transactionID);
          result.success(fetchResult);
        } else {
          result.error("Approov.waitForFetchValue", "Token fetch interrupted", null);
        }
      } else {
        result.error("Approov.waitForFetchValue", "No fetch in progress", null);
      }
    } else {
      result.notImplemented();
    }
  }
}
