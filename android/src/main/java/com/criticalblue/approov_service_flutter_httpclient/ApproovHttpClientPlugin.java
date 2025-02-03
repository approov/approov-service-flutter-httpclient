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
  private class CertificatePrefetcher implements Runnable {
    // Connect timeout (in ms) for host certificate fetch
    private static final int FETCH_CERTIFICATES_TIMEOUT_MS = 3000;

    // URL being probed for the certificates
    private final URL url;

    // Latch to signal completion of the certificate fetch
    private final CountDownLatch countDownLatch;

    // Any exception from the fetching process, or null otherwise
    private Exception exception;

    // The host certificates that were fetched, or null if there was an error
    private final List<byte[]> hostCertificates;

    /**
     * Constructor for the CertificatePrefetcher, which sets up ready for ansynchronous
     * execution.
     * 
     * @param url The URL to fetch the certificates from.
     */
    public CertificatePrefetcher(URL url) {
      this.url = url;
      hostCertificates = new ArrayList<>();
      exception = null;
      countDownLatch = new CountDownLatch(1);
    }

    /**
     * Runs the prefetcher to fetch the certificates from the URL.
     */
    @Override
    public void run() {
      try {
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(FETCH_CERTIFICATES_TIMEOUT_MS);
        connection.connect();
        Certificate[] certificates = connection.getServerCertificates();
        for (Certificate certificate: certificates) {
          hostCertificates.add(certificate.getEncoded());
        }
        connection.disconnect();
        countDownLatch.countDown();
      } catch (Exception e) {
        exception = e;
        countDownLatch.countDown();
      }
    }

    /**
     * Waits for the certificate fetch to complete and returns the exception if there was one.
     * 
     * @return The exception from the fetch, or nil if there was no exception
     */
    public Exception getResultException() {
      try {
        countDownLatch.await();
        return exception;
      } catch (InterruptedException e) {
        return e;
      }
    }

    /**
     * Returns the host certificates that were fetched. Note that this should only be called after
     * getResultException to make sure the results have been waited on.
     * 
     * @return The host certificates that were fetched.
     */
    public List<byte[]> getResultCertificates() {
      return hostCertificates;
    }
  }

  /**
   * Utility class for providing a callback handler for receiving a token fetch result on an
   * internal asynchronous request. This is for the prefetch case where the actual result is
   * not required.
   */
  private class InternalCallbackHandler implements Approov.TokenFetchCallback {
    /**
     * Construct a new internal callback handler.
     */
    InternalCallbackHandler() {
    }

    @Override
    public void approovCallback(Approov.TokenFetchResult pResult) {
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

  // Map of hostname to current in-flight certificate prefetchers
  private static Map<String, CertificatePrefetcher> certificatePrefetchers;

  @Override
  public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
    BinaryMessenger messenger = flutterPluginBinding.getBinaryMessenger();
    channel = new MethodChannel(messenger, "approov_service_flutter_httpclient",
              StandardMethodCodec.INSTANCE, messenger.makeBackgroundTaskQueue());
    channel.setMethodCallHandler(this);
    appContext = flutterPluginBinding.getApplicationContext();
    certificatePrefetchers = new HashMap<>();
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
    } else if (call.method.equals("fetchApproovToken")) {
      try {
        Approov.fetchApproovToken(new InternalCallbackHandler(), call.argument("url"));
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.fetchApproovToken", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchApproovTokenAndWait")) {
      try {
        Approov.TokenFetchResult tokenFetchResult = Approov.fetchApproovTokenAndWait(call.argument("url"));
        HashMap<String, Object> tokenFetchResultMap = new HashMap<>();
        tokenFetchResultMap.put("TokenFetchStatus", tokenFetchResult.getStatus().toString());
        tokenFetchResultMap.put("Token", tokenFetchResult.getToken());
        tokenFetchResultMap.put("SecureString", tokenFetchResult.getSecureString());
        tokenFetchResultMap.put("ARC", tokenFetchResult.getARC());
        tokenFetchResultMap.put("RejectionReasons", tokenFetchResult.getRejectionReasons());
        tokenFetchResultMap.put("IsConfigChanged", tokenFetchResult.isConfigChanged());
        tokenFetchResultMap.put("IsForceApplyPins", tokenFetchResult.isForceApplyPins());
        tokenFetchResultMap.put("MeasurementConfig", tokenFetchResult.getMeasurementConfig());
        tokenFetchResultMap.put("LoggableToken", tokenFetchResult.getLoggableToken());
        result.success(tokenFetchResultMap);
      } catch(Exception e) {
        result.error("Approov.fetchApproovTokenAndWait", e.getLocalizedMessage(), null);
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
    } else if (call.method.equals("prefetchHostCertificates")) {
      try {
        final URL url = new URL(call.argument("url"));
        CertificatePrefetcher certPrefetcher = certificatePrefetchers.get(url.getHost());
        if (certPrefetcher == null) {
          certPrefetcher = new CertificatePrefetcher(url);
          certificatePrefetchers.put(url.getHost(), certPrefetcher);
          new Thread(certPrefetcher).start();
        }
        result.success(null);
      } catch(Exception e) {
        result.error("Approov.prefetchHostCertificates", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchHostCertificates")) {
      try {
        final URL url = new URL(call.argument("url"));
        CertificatePrefetcher certPrefetcher = certificatePrefetchers.get(url.getHost());
        if (certPrefetcher == null) {
          certPrefetcher = new CertificatePrefetcher(url);
          new Thread(certPrefetcher).start();
        } else {
          certificatePrefetchers.remove(url.getHost());
        }
        Exception exception = certPrefetcher.getResultException();
        if (exception != null) {
          result.error("Approov.fetchHostCertificates", exception.getLocalizedMessage(), null);
        } else {
          List<byte[]> hostCertificates = certPrefetcher.getResultCertificates();
          result.success(hostCertificates);
        }
      } catch(Exception e) {
        result.error("Approov.fetchHostCertificatesy", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchSecureStringAndWait")) {
      try {
        Approov.TokenFetchResult tokenFetchResult = Approov.fetchSecureStringAndWait(call.argument("key"), call.argument("newDef"));
        HashMap<String, Object> fetchResultMap = new HashMap<>();
        fetchResultMap.put("TokenFetchStatus", tokenFetchResult.getStatus().toString());
        fetchResultMap.put("Token", tokenFetchResult.getToken());
        fetchResultMap.put("SecureString", tokenFetchResult.getSecureString());
        fetchResultMap.put("ARC", tokenFetchResult.getARC());
        fetchResultMap.put("RejectionReasons", tokenFetchResult.getRejectionReasons());
        fetchResultMap.put("IsConfigChanged", tokenFetchResult.isConfigChanged());
        fetchResultMap.put("IsForceApplyPins", tokenFetchResult.isForceApplyPins());
        fetchResultMap.put("LoggableToken", tokenFetchResult.getLoggableToken());
        result.success(fetchResultMap);
      } catch(Exception e) {
        result.error("Approov.fetchSecureStringAndWait", e.getLocalizedMessage(), null);
      }
    } else if (call.method.equals("fetchCustomJWTAndWait")) {
      try {
        Approov.TokenFetchResult tokenFetchResult = Approov.fetchCustomJWTAndWait(call.argument("payload"));
        HashMap<String, Object> tokenFetchResultMap = new HashMap<>();
        tokenFetchResultMap.put("TokenFetchStatus", tokenFetchResult.getStatus().toString());
        tokenFetchResultMap.put("Token", tokenFetchResult.getToken());
        tokenFetchResultMap.put("SecureString", tokenFetchResult.getSecureString());
        tokenFetchResultMap.put("ARC", tokenFetchResult.getARC());
        tokenFetchResultMap.put("RejectionReasons", tokenFetchResult.getRejectionReasons());
        tokenFetchResultMap.put("IsConfigChanged", tokenFetchResult.isConfigChanged());
        tokenFetchResultMap.put("IsForceApplyPins", tokenFetchResult.isForceApplyPins());
        tokenFetchResultMap.put("MeasurementConfig", tokenFetchResult.getMeasurementConfig());
        tokenFetchResultMap.put("LoggableToken", tokenFetchResult.getLoggableToken());
        result.success(tokenFetchResultMap);
      } catch(Exception e) {
        result.error("Approov.fetchCustomJWTAndWait", e.getLocalizedMessage(), null);
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
