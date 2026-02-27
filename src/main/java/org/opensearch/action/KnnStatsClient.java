/*
 * Copyright [2024] [Ably]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.Nullable;
import org.opensearch.common.SuppressForbidden;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * HTTP client for fetching KNN stats from the local OpenSearch node.
 *
 * Uses HttpURLConnection to call GET _plugins/_knn/stats on localhost.
 * HttpURLConnection is used instead of java.net.http.HttpClient because
 * HttpClient's internal code runs on the PlatformClassLoader which does not
 * inherit plugin security permissions, causing SecurityException under
 * OpenSearch's SecurityManager.
 *
 * The KNN plugin is optional - if not installed, HTTP 404 is returned and KNN metrics are skipped.
 */
public class KnnStatsClient {

    private static final Logger logger = LogManager.getLogger(KnnStatsClient.class);
    private static final int TIMEOUT_MS = 3000;
    private static final AtomicBoolean knnNotAvailableLogged = new AtomicBoolean(false);
    private static volatile SSLContext trustAllSslContext;

    private KnnStatsClient() {
        // utility class
    }

    /**
     * Fetch KNN stats from the local OpenSearch node via HTTP.
     *
     * @param scheme     "http" or "https"
     * @param port       local HTTP port
     * @param authHeader Authorization header value (may be null)
     * @param nodeFilter node filter string (e.g. nodeId for _local, or empty for _all)
     * @return parsed KnnStatsData, or null if KNN is not available or on error
     */
    @Nullable
    @SuppressWarnings("removal")
    public static KnnStatsData fetchKnnStats(String scheme, int port,
                                              @Nullable String authHeader,
                                              @Nullable String nodeFilter) {
        return AccessController.doPrivileged((PrivilegedAction<KnnStatsData>) () ->
                doFetchKnnStats(scheme, port, authHeader, nodeFilter));
    }

    @Nullable
    private static KnnStatsData doFetchKnnStats(String scheme, int port,
                                                 @Nullable String authHeader,
                                                 @Nullable String nodeFilter) {
        try {
            String path = "/_plugins/_knn/stats";
            if (nodeFilter != null && !nodeFilter.isEmpty()) {
                path = "/_plugins/_knn/" + nodeFilter + "/stats";
            }

            URL url = new URL(scheme, "127.0.0.1", port, path);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            if (conn instanceof HttpsURLConnection) {
                HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
                httpsConn.setSSLSocketFactory(getTrustAllSslContext().getSocketFactory());
                httpsConn.setHostnameVerifier((hostname, session) -> true);
            }

            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");

            if (authHeader != null && !authHeader.isEmpty()) {
                conn.setRequestProperty("Authorization", authHeader);
            }

            try {
                int statusCode = conn.getResponseCode();
                return handleResponse(conn, statusCode);
            } finally {
                conn.disconnect();
            }
        } catch (Exception e) {
            logger.warn("Failed to fetch KNN stats: {}", e.getMessage());
            return null;
        }
    }

    @Nullable
    private static KnnStatsData handleResponse(HttpURLConnection conn, int statusCode) {
        if (statusCode == 200) {
            try {
                String body = readResponseBody(conn);
                return KnnStatsData.parse(body);
            } catch (Exception e) {
                logger.warn("Failed to parse KNN stats response: {}", e.getMessage());
                return null;
            }
        }

        if (statusCode == 404) {
            if (knnNotAvailableLogged.compareAndSet(false, true)) {
                logger.info("KNN plugin not available (HTTP 404). KNN metrics will be skipped.");
            }
            return null;
        }

        if (statusCode == 401 || statusCode == 403) {
            logger.warn("KNN stats request failed with authentication/authorization error (HTTP {})", statusCode);
            return null;
        }

        logger.warn("KNN stats request failed with HTTP {}", statusCode);
        return null;
    }

    @SuppressForbidden(reason = "Need to read HTTP response body from KNN stats endpoint")
    private static String readResponseBody(HttpURLConnection conn) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }

    private static SSLContext getTrustAllSslContext() {
        if (trustAllSslContext == null) {
            synchronized (KnnStatsClient.class) {
                if (trustAllSslContext == null) {
                    trustAllSslContext = createTrustAllSslContext();
                }
            }
        }
        return trustAllSslContext;
    }

    private static SSLContext createTrustAllSslContext() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                            // trust all for localhost
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                            // trust all for localhost
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            return sslContext;
        } catch (Exception e) {
            logger.error("Failed to create trust-all SSLContext: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
