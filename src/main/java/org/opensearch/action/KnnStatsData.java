/*
 * Copyright [2018] [Vincent VAN HOLLEBEKE]
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

import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Parsed data from KNN stats API response ({@code GET _plugins/_knn/stats}).
 * This class is NOT a transport message; it is only used for local JSON parsing.
 */
public class KnnStatsData {

    // Cluster-level fields
    private boolean circuitBreakerTriggered;
    private final Map<String, KnnNodeStats> nodes = new HashMap<>();

    public boolean isCircuitBreakerTriggered() {
        return circuitBreakerTriggered;
    }

    public Map<String, KnnNodeStats> getNodes() {
        return nodes;
    }

    public static KnnStatsData parse(String jsonBody) throws IOException {
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(
                NamedXContentRegistry.EMPTY, DeprecationHandler.IGNORE_DEPRECATIONS, jsonBody)) {
            return parseInternal(parser);
        }
    }

    private static KnnStatsData parseInternal(XContentParser parser) throws IOException {
        KnnStatsData data = new KnnStatsData();
        XContentParser.Token token = parser.nextToken(); // START_OBJECT
        if (token != XContentParser.Token.START_OBJECT) {
            throw new IOException("Expected START_OBJECT but got " + token);
        }

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String field = parser.currentName();
            parser.nextToken();
            switch (field) {
                case "circuit_breaker_triggered":
                    data.circuitBreakerTriggered = parser.booleanValue();
                    break;
                case "nodes":
                    parseNodes(parser, data);
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }
        return data;
    }

    private static void parseNodes(XContentParser parser, KnnStatsData data) throws IOException {
        // parser is at START_OBJECT for "nodes"
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String nodeId = parser.currentName();
            parser.nextToken(); // START_OBJECT for this node
            KnnNodeStats nodeStats = KnnNodeStats.parse(parser);
            data.nodes.put(nodeId, nodeStats);
        }
    }

    // ---- Node-level stats ----

    public static class KnnNodeStats {
        long knnQueryRequests;
        long knnQueryWithFilterRequests;
        long graphQueryRequests;
        long graphQueryErrors;
        long scriptQueryRequests;
        long scriptQueryErrors;
        long minScoreQueryRequests;
        long minScoreQueryWithFilterRequests;
        long maxDistanceQueryRequests;
        long maxDistanceQueryWithFilterRequests;
        long graphIndexRequests;
        long graphIndexErrors;
        long hitCount;
        long missCount;
        long evictionCount;
        long loadSuccessCount;
        long loadExceptionCount;
        long totalLoadTime;
        boolean cacheCapacityReached;
        long graphMemoryUsage;
        double graphMemoryUsagePercentage;
        long trainingMemoryUsage;
        double trainingMemoryUsagePercentage;
        long trainingRequests;
        long trainingErrors;
        long scriptCompilations;
        long scriptCompilationErrors;
        boolean luceneInitialized;
        boolean faissInitialized;
        boolean nmslibInitialized;
        boolean indexingFromModelDegraded;
        GraphStats graphStats = new GraphStats();
        RemoteBuildStats remoteBuildStats = new RemoteBuildStats();
        Map<String, IndexCacheStats> indicesInCache = new HashMap<>();

        public long getKnnQueryRequests() { return knnQueryRequests; }
        public long getKnnQueryWithFilterRequests() { return knnQueryWithFilterRequests; }
        public long getGraphQueryRequests() { return graphQueryRequests; }
        public long getGraphQueryErrors() { return graphQueryErrors; }
        public long getScriptQueryRequests() { return scriptQueryRequests; }
        public long getScriptQueryErrors() { return scriptQueryErrors; }
        public long getMinScoreQueryRequests() { return minScoreQueryRequests; }
        public long getMinScoreQueryWithFilterRequests() { return minScoreQueryWithFilterRequests; }
        public long getMaxDistanceQueryRequests() { return maxDistanceQueryRequests; }
        public long getMaxDistanceQueryWithFilterRequests() { return maxDistanceQueryWithFilterRequests; }
        public long getGraphIndexRequests() { return graphIndexRequests; }
        public long getGraphIndexErrors() { return graphIndexErrors; }
        public long getHitCount() { return hitCount; }
        public long getMissCount() { return missCount; }
        public long getEvictionCount() { return evictionCount; }
        public long getLoadSuccessCount() { return loadSuccessCount; }
        public long getLoadExceptionCount() { return loadExceptionCount; }
        public long getTotalLoadTime() { return totalLoadTime; }
        public boolean isCacheCapacityReached() { return cacheCapacityReached; }
        public long getGraphMemoryUsage() { return graphMemoryUsage; }
        public double getGraphMemoryUsagePercentage() { return graphMemoryUsagePercentage; }
        public long getTrainingMemoryUsage() { return trainingMemoryUsage; }
        public double getTrainingMemoryUsagePercentage() { return trainingMemoryUsagePercentage; }
        public long getTrainingRequests() { return trainingRequests; }
        public long getTrainingErrors() { return trainingErrors; }
        public long getScriptCompilations() { return scriptCompilations; }
        public long getScriptCompilationErrors() { return scriptCompilationErrors; }
        public boolean isLuceneInitialized() { return luceneInitialized; }
        public boolean isFaissInitialized() { return faissInitialized; }
        public boolean isNmslibInitialized() { return nmslibInitialized; }
        public boolean isIndexingFromModelDegraded() { return indexingFromModelDegraded; }
        public GraphStats getGraphStats() { return graphStats; }
        public RemoteBuildStats getRemoteBuildStats() { return remoteBuildStats; }
        public Map<String, IndexCacheStats> getIndicesInCache() { return indicesInCache; }

        static KnnNodeStats parse(XContentParser parser) throws IOException {
            KnnNodeStats stats = new KnnNodeStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "knn_query_requests":
                        stats.knnQueryRequests = parser.longValue();
                        break;
                    case "knn_query_with_filter_requests":
                        stats.knnQueryWithFilterRequests = parser.longValue();
                        break;
                    case "graph_query_requests":
                        stats.graphQueryRequests = parser.longValue();
                        break;
                    case "graph_query_errors":
                        stats.graphQueryErrors = parser.longValue();
                        break;
                    case "script_query_requests":
                        stats.scriptQueryRequests = parser.longValue();
                        break;
                    case "script_query_errors":
                        stats.scriptQueryErrors = parser.longValue();
                        break;
                    case "min_score_query_requests":
                        stats.minScoreQueryRequests = parser.longValue();
                        break;
                    case "min_score_query_with_filter_requests":
                        stats.minScoreQueryWithFilterRequests = parser.longValue();
                        break;
                    case "max_distance_query_requests":
                        stats.maxDistanceQueryRequests = parser.longValue();
                        break;
                    case "max_distance_query_with_filter_requests":
                        stats.maxDistanceQueryWithFilterRequests = parser.longValue();
                        break;
                    case "graph_index_requests":
                        stats.graphIndexRequests = parser.longValue();
                        break;
                    case "graph_index_errors":
                        stats.graphIndexErrors = parser.longValue();
                        break;
                    case "hit_count":
                        stats.hitCount = parser.longValue();
                        break;
                    case "miss_count":
                        stats.missCount = parser.longValue();
                        break;
                    case "eviction_count":
                        stats.evictionCount = parser.longValue();
                        break;
                    case "load_success_count":
                        stats.loadSuccessCount = parser.longValue();
                        break;
                    case "load_exception_count":
                        stats.loadExceptionCount = parser.longValue();
                        break;
                    case "total_load_time":
                        stats.totalLoadTime = parser.longValue();
                        break;
                    case "cache_capacity_reached":
                        stats.cacheCapacityReached = parser.booleanValue();
                        break;
                    case "graph_memory_usage":
                        stats.graphMemoryUsage = parser.longValue();
                        break;
                    case "graph_memory_usage_percentage":
                        stats.graphMemoryUsagePercentage = parser.doubleValue();
                        break;
                    case "training_memory_usage":
                        stats.trainingMemoryUsage = parser.longValue();
                        break;
                    case "training_memory_usage_percentage":
                        stats.trainingMemoryUsagePercentage = parser.doubleValue();
                        break;
                    case "training_requests":
                        stats.trainingRequests = parser.longValue();
                        break;
                    case "training_errors":
                        stats.trainingErrors = parser.longValue();
                        break;
                    case "script_compilations":
                        stats.scriptCompilations = parser.longValue();
                        break;
                    case "script_compilation_errors":
                        stats.scriptCompilationErrors = parser.longValue();
                        break;
                    case "lucene_initialized":
                        stats.luceneInitialized = parser.booleanValue();
                        break;
                    case "faiss_initialized":
                        stats.faissInitialized = parser.booleanValue();
                        break;
                    case "nmslib_initialized":
                        stats.nmslibInitialized = parser.booleanValue();
                        break;
                    case "indexing_from_model_degraded":
                        stats.indexingFromModelDegraded = parser.booleanValue();
                        break;
                    case "graph_stats":
                        stats.graphStats = GraphStats.parse(parser);
                        break;
                    case "indices_in_cache":
                        stats.indicesInCache = IndexCacheStats.parseIndices(parser);
                        break;
                    case "remote_vector_index_build_stats":
                        stats.remoteBuildStats = RemoteBuildStats.parse(parser);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    // ---- Index cache stats (per index) ----

    public static class IndexCacheStats {
        long graphMemoryUsage;
        double graphMemoryUsagePercentage;
        long graphCount;

        public long getGraphMemoryUsage() { return graphMemoryUsage; }
        public double getGraphMemoryUsagePercentage() { return graphMemoryUsagePercentage; }
        public long getGraphCount() { return graphCount; }

        static Map<String, IndexCacheStats> parseIndices(XContentParser parser) throws IOException {
            Map<String, IndexCacheStats> indices = new HashMap<>();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String indexName = parser.currentName();
                parser.nextToken(); // START_OBJECT
                indices.put(indexName, parseIndex(parser));
            }
            return indices;
        }

        static IndexCacheStats parseIndex(XContentParser parser) throws IOException {
            IndexCacheStats stats = new IndexCacheStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "graph_memory_usage":
                        stats.graphMemoryUsage = parser.longValue();
                        break;
                    case "graph_memory_usage_percentage":
                        stats.graphMemoryUsagePercentage = parser.doubleValue();
                        break;
                    case "graph_count":
                        stats.graphCount = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    // ---- Graph stats (refresh + merge) ----

    public static class GraphStats {
        RefreshStats refresh = new RefreshStats();
        MergeStats merge = new MergeStats();

        public RefreshStats getRefresh() { return refresh; }
        public MergeStats getMerge() { return merge; }

        static GraphStats parse(XContentParser parser) throws IOException {
            GraphStats stats = new GraphStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "refresh":
                        stats.refresh = RefreshStats.parse(parser);
                        break;
                    case "merge":
                        stats.merge = MergeStats.parse(parser);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    public static class RefreshStats {
        long total;
        long totalTimeInMillis;

        public long getTotal() { return total; }
        public long getTotalTimeInMillis() { return totalTimeInMillis; }

        static RefreshStats parse(XContentParser parser) throws IOException {
            RefreshStats stats = new RefreshStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "total":
                        stats.total = parser.longValue();
                        break;
                    case "total_time_in_millis":
                        stats.totalTimeInMillis = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    public static class MergeStats {
        long current;
        long total;
        long totalTimeInMillis;
        long currentDocs;
        long totalDocs;
        long totalSizeInBytes;
        long currentSizeInBytes;

        public long getCurrent() { return current; }
        public long getTotal() { return total; }
        public long getTotalTimeInMillis() { return totalTimeInMillis; }
        public long getCurrentDocs() { return currentDocs; }
        public long getTotalDocs() { return totalDocs; }
        public long getTotalSizeInBytes() { return totalSizeInBytes; }
        public long getCurrentSizeInBytes() { return currentSizeInBytes; }

        static MergeStats parse(XContentParser parser) throws IOException {
            MergeStats stats = new MergeStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "current":
                        stats.current = parser.longValue();
                        break;
                    case "total":
                        stats.total = parser.longValue();
                        break;
                    case "total_time_in_millis":
                        stats.totalTimeInMillis = parser.longValue();
                        break;
                    case "current_docs":
                        stats.currentDocs = parser.longValue();
                        break;
                    case "total_docs":
                        stats.totalDocs = parser.longValue();
                        break;
                    case "total_size_in_bytes":
                        stats.totalSizeInBytes = parser.longValue();
                        break;
                    case "current_size_in_bytes":
                        stats.currentSizeInBytes = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    // ---- Remote vector index build stats ----

    public static class RemoteBuildStats {
        RepositoryStats repositoryStats = new RepositoryStats();
        BuildStats buildStats = new BuildStats();
        ClientStats clientStats = new ClientStats();

        public RepositoryStats getRepositoryStats() { return repositoryStats; }
        public BuildStats getBuildStats() { return buildStats; }
        public ClientStats getClientStats() { return clientStats; }

        static RemoteBuildStats parse(XContentParser parser) throws IOException {
            RemoteBuildStats stats = new RemoteBuildStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "repository_stats":
                        stats.repositoryStats = RepositoryStats.parse(parser);
                        break;
                    case "build_stats":
                        stats.buildStats = BuildStats.parse(parser);
                        break;
                    case "client_stats":
                        stats.clientStats = ClientStats.parse(parser);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    public static class RepositoryStats {
        long readSuccessCount;
        long readFailureCount;
        long successfulReadTimeInMillis;
        long writeSuccessCount;
        long writeFailureCount;
        long successfulWriteTimeInMillis;

        public long getReadSuccessCount() { return readSuccessCount; }
        public long getReadFailureCount() { return readFailureCount; }
        public long getSuccessfulReadTimeInMillis() { return successfulReadTimeInMillis; }
        public long getWriteSuccessCount() { return writeSuccessCount; }
        public long getWriteFailureCount() { return writeFailureCount; }
        public long getSuccessfulWriteTimeInMillis() { return successfulWriteTimeInMillis; }

        static RepositoryStats parse(XContentParser parser) throws IOException {
            RepositoryStats stats = new RepositoryStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "read_success_count":
                        stats.readSuccessCount = parser.longValue();
                        break;
                    case "read_failure_count":
                        stats.readFailureCount = parser.longValue();
                        break;
                    case "successful_read_time_in_millis":
                        stats.successfulReadTimeInMillis = parser.longValue();
                        break;
                    case "write_success_count":
                        stats.writeSuccessCount = parser.longValue();
                        break;
                    case "write_failure_count":
                        stats.writeFailureCount = parser.longValue();
                        break;
                    case "successful_write_time_in_millis":
                        stats.successfulWriteTimeInMillis = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    public static class BuildStats {
        long remoteIndexBuildFlushTimeInMillis;
        long remoteIndexBuildMergeTimeInMillis;
        long remoteIndexBuildCurrentMergeSize;
        long remoteIndexBuildCurrentMergeOperations;
        long remoteIndexBuildCurrentFlushOperations;
        long remoteIndexBuildCurrentFlushSize;

        public long getRemoteIndexBuildFlushTimeInMillis() { return remoteIndexBuildFlushTimeInMillis; }
        public long getRemoteIndexBuildMergeTimeInMillis() { return remoteIndexBuildMergeTimeInMillis; }
        public long getRemoteIndexBuildCurrentMergeSize() { return remoteIndexBuildCurrentMergeSize; }
        public long getRemoteIndexBuildCurrentMergeOperations() { return remoteIndexBuildCurrentMergeOperations; }
        public long getRemoteIndexBuildCurrentFlushOperations() { return remoteIndexBuildCurrentFlushOperations; }
        public long getRemoteIndexBuildCurrentFlushSize() { return remoteIndexBuildCurrentFlushSize; }

        static BuildStats parse(XContentParser parser) throws IOException {
            BuildStats stats = new BuildStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "remote_index_build_flush_time_in_millis":
                        stats.remoteIndexBuildFlushTimeInMillis = parser.longValue();
                        break;
                    case "remote_index_build_merge_time_in_millis":
                        stats.remoteIndexBuildMergeTimeInMillis = parser.longValue();
                        break;
                    case "remote_index_build_current_merge_size":
                        stats.remoteIndexBuildCurrentMergeSize = parser.longValue();
                        break;
                    case "remote_index_build_current_merge_operations":
                        stats.remoteIndexBuildCurrentMergeOperations = parser.longValue();
                        break;
                    case "remote_index_build_current_flush_operations":
                        stats.remoteIndexBuildCurrentFlushOperations = parser.longValue();
                        break;
                    case "remote_index_build_current_flush_size":
                        stats.remoteIndexBuildCurrentFlushSize = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }

    public static class ClientStats {
        long statusRequestSuccessCount;
        long statusRequestFailureCount;
        long indexBuildSuccessCount;
        long indexBuildFailureCount;
        long buildRequestSuccessCount;
        long buildRequestFailureCount;
        long waitingTimeInMs;

        public long getStatusRequestSuccessCount() { return statusRequestSuccessCount; }
        public long getStatusRequestFailureCount() { return statusRequestFailureCount; }
        public long getIndexBuildSuccessCount() { return indexBuildSuccessCount; }
        public long getIndexBuildFailureCount() { return indexBuildFailureCount; }
        public long getBuildRequestSuccessCount() { return buildRequestSuccessCount; }
        public long getBuildRequestFailureCount() { return buildRequestFailureCount; }
        public long getWaitingTimeInMs() { return waitingTimeInMs; }

        static ClientStats parse(XContentParser parser) throws IOException {
            ClientStats stats = new ClientStats();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                switch (field) {
                    case "status_request_success_count":
                        stats.statusRequestSuccessCount = parser.longValue();
                        break;
                    case "status_request_failure_count":
                        stats.statusRequestFailureCount = parser.longValue();
                        break;
                    case "index_build_success_count":
                        stats.indexBuildSuccessCount = parser.longValue();
                        break;
                    case "index_build_failure_count":
                        stats.indexBuildFailureCount = parser.longValue();
                        break;
                    case "build_request_success_count":
                        stats.buildRequestSuccessCount = parser.longValue();
                        break;
                    case "build_request_failure_count":
                        stats.buildRequestFailureCount = parser.longValue();
                        break;
                    case "waiting_time_in_ms":
                        stats.waitingTimeInMs = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
            return stats;
        }
    }
}
