package dev.sunbirdrc.elastic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import dev.sunbirdrc.pojos.Filter;
import dev.sunbirdrc.pojos.FilterOperators;
import dev.sunbirdrc.pojos.SearchQuery;
import dev.sunbirdrc.registry.middleware.util.Constants;
import dev.sunbirdrc.registry.middleware.util.JSONUtil;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.collections4.KeyValue;
import org.apache.commons.collections4.keyvalue.DefaultKeyValue;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.*;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ElasticServiceImpl implements IElasticService {
    private static Map<String, Set<String>> indexWiseExcludeFields = new HashMap<>();
    private static Map<String, RestHighLevelClient> esClient = new HashMap<String, RestHighLevelClient>();
    private static Logger logger = LoggerFactory.getLogger(ElasticServiceImpl.class);

    private static String connectionInfo;
    private static String searchType;
    private static boolean authEnabled;
    //private static boolean pathPrefixSet;
    private static String userName;
    private static String password;
    private static String defaultScheme;

    private static String jksFilePath;

    private static String trustStorePassword;

    private static boolean sslByPassSet = false;

    public void setConnectionInfo(String connection) {
        connectionInfo = connection;
    }

    public void setType(String type) {
        searchType = type;
    }

    /**
     * This method runs when the application is started in order to add all the indcies to the elastic search
     *
     * @param indices
     * @throws RuntimeException
     */
    public void init(Set<String> indices, Map<String, Set<String>> indexWiseExcludeFields) throws RuntimeException {
        this.indexWiseExcludeFields = indexWiseExcludeFields;
        indices.iterator().forEachRemaining(index -> {
            try {
                addIndex(index.toLowerCase(), searchType);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Ideally this needs to be set via configuration
     * In case ssl certificates are not part of chain
     * locally created we need mechanism to allow for
     * bypassing them.
     *
     * This method will treat all ssl context as valid.
     */
    /*static void byPassSSL() {
        if (sslByPassSet)
            return;
        logger.info("By Pass SSL");
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    @Override
                    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
                            throws CertificateException {}

                    @Override
                    public void checkServerTrusted(X509Certificate[] arg0, String arg1)
                            throws CertificateException {}
                }
        };

        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("SSL");
            logger.info("ssl context set...");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            assert sc != null;
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // Create all-trusting host name verifier
        HostnameVerifier validHosts = (arg0, arg1) -> {
            logger.info("verify host: {}", arg0);
            logger.info("ssl session: {}", arg1);
            return true;
        };
        // All hosts will be valid
        HttpsURLConnection.setDefaultHostnameVerifier(validHosts);
        sslByPassSet = true;
    }*/


    /**
     * This method creates the high-level-client w.r.to index, if client is not created. for every index one client object is created
     *
     * @param indexName      for ElasticSearch
     * @param connectionInfo of ElasticSearch
     */
    private static void createClient(String indexName, String connectionInfo) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, KeyManagementException {
        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials(userName, password));
        boolean usingSSH = defaultScheme.equalsIgnoreCase("https");
        if (!esClient.containsKey(indexName)) {
            // KeyValue key is port and value is scheme type.
            Map<String, KeyValue<Integer, String>> hostPort = new HashMap<>();
            for (String info : connectionInfo.split(",")) {
                // use URL to get sceme/protocol if defined else fall back to earlier mechanism
                // of configuring host/port
                try {
                    URL url = new URL(info);
                    usingSSH |= url.getProtocol().equalsIgnoreCase("https");
                    hostPort.put(url.getHost(), new DefaultKeyValue<>(url.getPort(), url.getProtocol()));
                } catch (Exception e) {
                    hostPort.put(info.split(":")[0], new DefaultKeyValue<>(Integer.valueOf(info.split(":")[1]), defaultScheme));
                }
            }
            List<HttpHost> httpHosts = new ArrayList<>();
            for (String host : hostPort.keySet()) {
                httpHosts.add(new HttpHost(host, hostPort.get(host).getKey(), hostPort.get(host).getValue()));
            }

            KeyStore trustStore = KeyStore.getInstance("jks");

            InputStream is = new FileInputStream(jksFilePath);
            trustStore.load(is, trustStorePassword.toCharArray());

            SSLContextBuilder sslContextBuilder = SSLContexts.custom().loadTrustMaterial(trustStore, null);

            SSLContext sslContext = sslContextBuilder.build();

            /*if (usingSSH)
                byPassSSL();*/
            RestClientBuilder restClientBuilder = RestClient.builder(httpHosts.toArray(new HttpHost[httpHosts.size()]));


            /*if (pathPrefixSet) {
                restClientBuilder.setPathPrefix(pathPrefix);
            }*/
            if(authEnabled) {
                restClientBuilder.setHttpClientConfigCallback(
                        httpAsyncClientBuilder -> httpAsyncClientBuilder.setDefaultCredentialsProvider(credentialsProvider)
                                .setSSLContext(sslContext)
                );
            }
            RestHighLevelClient client = new RestHighLevelClient(restClientBuilder);
            if (null != client)
                esClient.put(indexName, client);
        }
    }

    /**
     * Get client details from map
     *
     * @param indexName of ElasticSearch
     * @return
     */
    private static RestHighLevelClient getClient(String indexName)  {
        logger.info("connection info: index:{} connectioninfo:{}", indexName, connectionInfo);
        if (null == esClient.get(indexName)) {
            try {
                createClient(indexName, connectionInfo);
            } catch (Exception any) {
                logger.warn("Failed to create client: {}", any.getMessage(), any);
                return null;
            }
        }
        logger.info("resthighclient obj:" + esClient.get(indexName));
        return esClient.get(indexName);
    }

    /**
     * creates index for elastic-search
     *
     * @param indexName    of ElasticSearch
     * @param documentType of ElasticSearch
     * @return
     * @throws IOException
     */
    @Retryable(value = {IOException.class, ConnectException.class}, maxAttemptsExpression = "#{${service.retry.maxAttempts}}",
            backoff = @Backoff(delayExpression = "#{${service.retry.backoff.delay}}"))
    public static boolean addIndex(String indexName, String documentType) throws IOException {
        boolean response = false;
        //To do need to analysis regarding settings and analysis and modify this code later
        /*String settings = "{\"analysis\": {       \"analyzer\": {         \"doc_index_analyzer\": {           \"type\": \"custom\",           \"tokenizer\": \"standard\",           \"filter\": [             \"lowercase\",             \"mynGram\"           ]         },         \"doc_search_analyzer\": {           \"type\": \"custom\",           \"tokenizer\": \"standard\",           \"filter\": [             \"standard\",             \"lowercase\"           ]         },         \"keylower\": {           \"tokenizer\": \"keyword\",           \"filter\": \"lowercase\"         }       },       \"filter\": {         \"mynGram\": {           \"type\": \"nGram\",           \"min_gram\": 1,           \"max_gram\": 20,           \"token_chars\": [             \"letter\",             \"digit\",             \"whitespace\",             \"punctuation\",             \"symbol\"           ]         }       }     }   }";
        String mappings = "{\"dynamic_templates\":[{\"longs\":{\"match_mapping_type\":\"long\",\"mapping\":{\"type\":\"long\",\"fields\":{\"raw\":{\"type\":\"long\"}}}}},{\"booleans\":{\"match_mapping_type\":\"boolean\",\"mapping\":{\"type\":\"boolean\",\"fields\":{\"raw\":{\"type\":\"boolean\"}}}}},{\"doubles\":{\"match_mapping_type\":\"double\",\"mapping\":{\"type\":\"double\",\"fields\":{\"raw\":{\"type\":\"double\"}}}}},{\"dates\":{\"match_mapping_type\":\"date\",\"mapping\":{\"type\":\"date\",\"fields\":{\"raw\":{\"type\":\"date\"}}}}},{\"strings\":{\"match_mapping_type\":\"string\",\"mapping\":{\"type\":\"text\",\"copy_to\":\"all_fields\",\"analyzer\":\"doc_index_analyzer\",\"search_analyzer\":\"doc_search_analyzer\",\"fields\":{\"raw\":{\"type\":\"text\",\"analyzer\":\"keylower\"}}}}}],\"properties\":{\"all_fields\":{\"type\":\"text\",\"analyzer\":\"doc_index_analyzer\",\"search_analyzer\":\"doc_search_analyzer\",\"fields\":{\"raw\":{\"type\":\"text\",\"analyzer\":\"keylower\"}}}}}";*/
        RestHighLevelClient client = getClient(indexName);
        if (!isIndexExists(indexName)) {
            CreateIndexRequest createRequest = new CreateIndexRequest(indexName);

            /*if (StringUtils.isNotBlank(settings))
               createRequest.settings(Settings.builder().loadFromSource(settings, XContentType.JSON));
            if (StringUtils.isNotBlank(documentType) && StringUtils.isNotBlank(mappings))
                createRequest.mapping(documentType, mappings, XContentType.JSON);*/
            CreateIndexResponse createIndexResponse = client.indices().create(createRequest, RequestOptions.DEFAULT);

            response = createIndexResponse.isAcknowledged();
        }
        return response;
    }

    /**
     * checks whether input index exists in the elastic-search
     *
     * @param indexName of elastic-search
     * @return
     */
    public static boolean isIndexExists(String indexName) {
        Response response;
        try {
            response = getClient(indexName).getLowLevelClient().performRequest(new Request("HEAD", "/" + indexName));
            return (200 == response.getStatusLine().getStatusCode());
        } catch (IOException e) {
            return false;
        }

    }

    /**
     * Adds input as document into elastic-search
     *
     * @param index       - ElasticSearch Index
     * @param entityId    - entity id as document id
     * @param inputEntity - input document for adding
     * @return
     */
    @Override
    public RestStatus addEntity(String index, String entityId, JsonNode inputEntity) {
        logger.debug("addEntity starts with index {} and entityId {}", index, entityId);
        IndexResponse response = null;
        try {
            DocumentContext doc = getDocumentContextAfterRemovingExcludedFields(index, inputEntity);
            JsonNode filteredNode = JSONUtil.convertStringJsonNode(doc.jsonString());
            Map<String, Object> inputMap = JSONUtil.convertJsonNodeToMap(filteredNode);
            response = getClient(index).index(new IndexRequest(index, searchType, entityId).source(inputMap), RequestOptions.DEFAULT);
        } catch (IOException e) {
            logger.error("Exception in adding record to ElasticSearch", e);
        }
        return response.status();
    }

    /**
     * Reads the document from Elastic search
     *
     * @param index - ElasticSearch Index
     * @param osid  - which maps to document
     * @return
     */
    @Override
    @Retryable(value = {IOException.class, ConnectException.class}, maxAttemptsExpression = "#{${service.retry.maxAttempts}}",
            backoff = @Backoff(delayExpression = "#{${service.retry.backoff.delay}}"))
    public Map<String, Object> readEntity(String index, String osid) throws IOException {
        logger.debug("readEntity starts with index {} and entityId {}", index, osid);

        GetResponse response = null;
        response = getClient(index).get(new GetRequest(index, searchType, osid), RequestOptions.DEFAULT);
        return response.getSourceAsMap();
    }


    /**
     * Updates the document with updated inputEntity
     *
     * @param index       - ElasticSearch Index
     * @param osid        - which maps to document
     * @param inputEntity - input json document for updating
     * @return
     */
    @Override
    public RestStatus updateEntity(String index, String osid, JsonNode inputEntity) {
        logger.debug("updateEntity starts with index {} and entityId {}", index, osid);
        UpdateResponse response = null;
        try {
            DocumentContext doc = getDocumentContextAfterRemovingExcludedFields(index, inputEntity);
            JsonNode filteredNode = JSONUtil.convertStringJsonNode(doc.jsonString());
            Map<String, Object> inputMap = JSONUtil.convertJsonNodeToMap(filteredNode);
            logger.debug("updateEntity inputMap {}", inputMap);
            logger.debug("updateEntity inputEntity {}", inputEntity);
            response = getClient(index.toLowerCase()).update(new UpdateRequest(index.toLowerCase(), searchType, osid).doc(inputMap), RequestOptions.DEFAULT);
        } catch (IOException e) {
            logger.error("Exception in updating a record to ElasticSearch", e);
        }
        return response.status();
    }

    private DocumentContext getDocumentContextAfterRemovingExcludedFields(String index, JsonNode inputEntity) throws com.fasterxml.jackson.core.JsonProcessingException {
        DocumentContext doc = JsonPath.parse(JSONUtil.convertObjectJsonString(inputEntity));
        for (String jsonPath : indexWiseExcludeFields.get(index)) {
            try {
                doc.delete(jsonPath);
            } catch (Exception e) {
                logger.error("Path not found {} {}", jsonPath, e.getMessage());
            }
        }
        return doc;
    }

    /**
     * Updates the document status to inactive into elastic-search
     *
     * @param index - ElasticSearch Index
     * @param osid  - which maps to document
     * @return
     */
    @Override
    public RestStatus deleteEntity(String index, String osid) {
        UpdateResponse response = null;
        try {
            String indexL = index.toLowerCase();
            Map<String, Object> readMap = readEntity(indexL, osid);
           // Map<String, Object> entityMap = (Map<String, Object>) readMap.get(index);
            readMap.put(Constants.STATUS_KEYWORD, Constants.STATUS_INACTIVE);
            response = getClient(indexL).update(new UpdateRequest(indexL, searchType, osid).doc(readMap), RequestOptions.DEFAULT);
        } catch (NullPointerException | IOException e) {
            logger.error("exception in deleteEntity {}", e);
            return RestStatus.NOT_FOUND;
        }
        return response.status();
    }

    @Override
    @Retryable(value = {IOException.class, ConnectException.class}, maxAttemptsExpression = "#{${service.retry.maxAttempts}}",
            backoff = @Backoff(delayExpression = "#{${service.retry.backoff.delay}}"))
    public JsonNode search(String index, SearchQuery searchQuery) throws IOException {
        BoolQueryBuilder query = buildQuery(searchQuery);

        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder()
                .query(query)
                .size(searchQuery.getLimit())
                .from(searchQuery.getOffset());
        SearchRequest searchRequest = new SearchRequest(index).source(sourceBuilder);
        ArrayNode resultArray = JsonNodeFactory.instance.arrayNode();
        ObjectMapper mapper = new ObjectMapper();
            SearchResponse searchResponse = getClient(index).search(searchRequest, RequestOptions.DEFAULT);
            for (SearchHit hit : searchResponse.getHits()) {
                JsonNode node = mapper.readValue(hit.getSourceAsString(), JsonNode.class);
                // TODO: Add draft mode condition
                if(node.get("_status") == null || node.get("_status").asBoolean()) {
                    resultArray.add(node);
                }
            }
            logger.debug("Total search records found " + resultArray.size());

        return resultArray;

    }

    /**
     * Builds the final query builder for given searchQuery
     *
     * @param searchQuery
     * @return
     */
    private BoolQueryBuilder buildQuery(SearchQuery searchQuery) {
        List<Filter> filters = searchQuery.getFilters();
        BoolQueryBuilder query = QueryBuilders.boolQuery();

        for (Filter filter : filters) {
            String field = filter.getProperty();
            Object value = filter.getValue();
            FilterOperators operator = filter.getOperator();
            String path = filter.getPath();

            if (path != null) {
                field = path + "." + field;
            }
            switch (operator) {
            case eq:
                query = query.must(QueryBuilders.matchPhraseQuery(field, value));
                break;
            case neq:
                query = query.mustNot(QueryBuilders.matchPhraseQuery(field, value));
                break;
            case gt:
                query = query.must(QueryBuilders.rangeQuery(field).gt(value));
                break;
            case lt:
                query = query.must(QueryBuilders.rangeQuery(field).lt(value));
                break;
            case gte:
                query = query.must(QueryBuilders.rangeQuery(field).gte(value));
                break;
            case lte:
                query = query.must(QueryBuilders.rangeQuery(field).lte(value));
                break;
            case between:
                List<Object> objects = (List<Object>) value;
                query = query
                        .must(QueryBuilders.rangeQuery(field).from(objects.get(0)).to(objects.get(objects.size() - 1)));
                break;
            case or:
                List<Object> values = (List<Object>) value;
                query = query.must(QueryBuilders.termsQuery(String.format("%s.keyword", field), values));
                break;

            case contains:
                query = query.must(QueryBuilders.matchPhraseQuery(field, value));
                break;
            case startsWith:
                query = query.must(QueryBuilders.matchPhrasePrefixQuery(field, value.toString()));
                break;
            case endsWith:
                query = query.must(QueryBuilders.wildcardQuery(field, "*" + value));
                break;
            case notContains:
                query = query.mustNot(QueryBuilders.matchPhraseQuery(field, value));
                break;
            case notStartsWith:
                query = query.mustNot(QueryBuilders.matchPhrasePrefixQuery(field, value.toString()));
                break;
            case notEndsWith:
                query = query.mustNot(QueryBuilders.wildcardQuery(field, "*" + value));
                break;
            case queryString:
                query = query.must(QueryBuilders.queryStringQuery(value.toString()));
                break;
            default:
                query = query.must(QueryBuilders.matchQuery(field, value));
                break;
            }
        }

        return query;
    }

    public void setAuthEnabled(boolean authEnabled) {
        this.authEnabled = authEnabled;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * set default scheme used in setting protocol for RestHighEndClient
     * @param scheme
     */
    public void setScheme(String scheme) {
        this.defaultScheme = scheme;
    }

    public void setJksFilePath(String jksFilePath) {
        this.jksFilePath = jksFilePath;
    }

    public  void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }
}
