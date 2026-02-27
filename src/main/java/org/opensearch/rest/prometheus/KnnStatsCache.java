/*
 * Copyright [2026] [Ably]
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

package org.opensearch.rest.prometheus;

import org.opensearch.action.KnnStatsClient;
import org.opensearch.action.KnnStatsData;
import org.opensearch.common.Nullable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Lightweight cache for KNN stats to decouple scrape requests from HTTP loopback calls.
 * The cache refreshes asynchronously when stale, and serves the last successful result.
 */
public class KnnStatsCache {

    private static final Logger logger = LogManager.getLogger(KnnStatsCache.class);

    private static class Context {
        final String scheme;
        final int port;
        final String authHeader;
        final String nodeFilter;

        Context(String scheme, int port, @Nullable String authHeader, @Nullable String nodeFilter) {
            this.scheme = scheme;
            this.port = port;
            this.authHeader = authHeader;
            this.nodeFilter = nodeFilter;
        }
    }

    private final long refreshIntervalMillis;
    private final ScheduledExecutorService scheduler;
    private final AtomicReference<KnnStatsData> cache = new AtomicReference<>();
    private final AtomicLong lastSuccessAt = new AtomicLong(0);
    private final AtomicReference<Context> lastContext = new AtomicReference<>();
    private final AtomicBoolean refreshRunning = new AtomicBoolean(false);

    public KnnStatsCache(long refreshIntervalMillis) {
        this.refreshIntervalMillis = refreshIntervalMillis;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "knn-stats-cache");
                t.setDaemon(true);
                return t;
            }
        });
    }

    public void updateContext(String scheme, int port, @Nullable String authHeader, @Nullable String nodeFilter) {
        lastContext.set(new Context(scheme, port, authHeader, nodeFilter));
    }

    @Nullable
    public KnnStatsData getOrFetch() {
        KnnStatsData existing = cache.get();
        if (existing == null) {
            KnnStatsData data = fetchAndStore();
            if (data == null) {
                logger.warn("KNN stats cache is empty and fetch failed; KNN metrics will be skipped");
            }
            return data;
        }

        long now = System.currentTimeMillis();
        if (now - lastSuccessAt.get() >= refreshIntervalMillis) {
            triggerRefreshAsync();
        }
        return existing;
    }

    private void triggerRefreshAsync() {
        if (!refreshRunning.compareAndSet(false, true)) {
            return;
        }
        scheduler.execute(() -> {
            try {
                fetchAndStore();
            } finally {
                refreshRunning.set(false);
            }
        });
    }

    @Nullable
    private KnnStatsData fetchAndStore() {
        Context ctx = lastContext.get();
        if (ctx == null) {
            logger.warn("KNN stats fetch skipped: context not initialized");
            return null;
        }

        KnnStatsData data = KnnStatsClient.fetchKnnStats(
                ctx.scheme, ctx.port, ctx.authHeader, ctx.nodeFilter);
        if (data != null) {
            cache.set(data);
            lastSuccessAt.set(System.currentTimeMillis());
        } else {
            logger.warn("KNN stats fetch failed; keeping last cached value");
        }
        return data;
    }
}
