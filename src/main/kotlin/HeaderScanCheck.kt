import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import java.io.File
import java.io.InputStream
import java.util.*

class HeaderScanCheck internal constructor(private val api: MontoyaApi, private val dataHolder: DataHolder) :
    ScanCheck {
    private val persistedStorage: PersistedObject
    private var persistedHeaderList: PersistedList<String>
    private var headers: List<HeaderSecurityConfig>
    private var hostnameList: List<String>
    private val logger: Logging = api.logging()
    private var headerConfigFilePath: String = ""
    private val CSV_SEPARATOR = "\u001F"
    private val HOSTNAME_SEPARATOR = ";"

    init {
        persistedStorage = this.api.persistence().extensionData()
        if (persistedStorage.getStringList(PersistenceConfig.PERSISTED_STORAGE.value) != null) {
            persistedHeaderList = persistedStorage.getStringList(PersistenceConfig.PERSISTED_STORAGE.value)
        } else {
            logger.logToOutput("Persisted storage seems to be null")
            persistedHeaderList = PersistedList.persistedStringList()
            persistedStorage.setStringList(PersistenceConfig.PERSISTED_STORAGE.value, persistedHeaderList)
        }
        if(persistedStorage.getString(PersistenceConfig.PERSISTED_CONFIG_PATH.value) != null) {
            dataHolder.configFilePath = persistedStorage.getString(PersistenceConfig.PERSISTED_CONFIG_PATH.value)
        }
        if(persistedStorage.getString(PersistenceConfig.PERSISTED_HOSTNAMES.value) != null) {
            dataHolder.hostnames = persistedStorage.getString(PersistenceConfig.PERSISTED_HOSTNAMES.value)
        }
        if(persistedStorage.getBoolean(PersistenceConfig.PERSISTED_CREATE_ISSUES.value) != null){
            dataHolder.shouldCreateIssues = persistedStorage.getBoolean(PersistenceConfig.PERSISTED_CREATE_ISSUES.value)
        }

        val inputStream = javaClass.getResourceAsStream("/HeaderMate_config.csv")
            ?: throw IllegalStateException("Resource HeaderMate_config.csv not found in classpath!")
        headers = configureHeaderScans(inputStream)
        hostnameList = dataHolder.hostnames.split(HOSTNAME_SEPARATOR)
    }

    override fun activeAudit(
        httpRequestResponse: HttpRequestResponse?,
        auditInsertionPoint: AuditInsertionPoint?
    ): AuditResult? {
        return AuditResult.auditResult();
    }

    override fun passiveAudit(httpRequestResponse: HttpRequestResponse): AuditResult? {
        val auditIssueList = ArrayList<AuditIssue>()
        if (dataHolder.hasContentChanged) {
            hostnameList = dataHolder.hostnames.split(HOSTNAME_SEPARATOR)
            if (!dataHolder.configFilePath.isEmpty()) {
                headerConfigFilePath = dataHolder.configFilePath
                headers = configureHeaderScans(headerConfigFilePath)
            }
            dataHolder.hasContentChanged = false
            logger.logToOutput("HeaderMate settings have changed and reloaded")
            logger.logToOutput("Should create issues: " + dataHolder.shouldCreateIssues)
        }
        if (httpRequestResponse.response() != null && shouldHostBeChecked(
                httpRequestResponse.request(),
                hostnameList
            )
        ) {
            // check defined list of headers
            for (header: HeaderSecurityConfig in headers) {
                val responseHighlights = getResponseHighlights(httpRequestResponse, header.headerName)
                //Header is not present
                if (responseHighlights.isEmpty()) {
                    addToPersistenceStorage(
                        httpRequestResponse.request().headerValue("Host").toString(),
                        httpRequestResponse.request().path(),
                        httpRequestResponse.response().statusCode(),
                        header.headerName,
                        HeaderConfig.EMPTY.value
                    )
                    if(dataHolder.shouldCreateIssues) {
                        var auditSeverityEmptyHeader = header.getSeverityOfValue(HeaderConfig.EMPTY.value)
                        if (auditSeverityEmptyHeader == AuditIssueSeverity.FALSE_POSITIVE) {
                            logger.logToOutput("Header is empty or not set at all and no severity could be assigned. Header: " + header.headerName + " Full response: " + httpRequestResponse.response())
                        }
                        // Header is empty and has severity --> create issue
                        if (auditSeverityEmptyHeader != AuditIssueSeverity.FALSE_POSITIVE) {
                            auditIssueList.add(
                                generateAuditIssueNotSet(
                                    header.headerName,
                                    header.optimalValue,
                                    auditSeverityEmptyHeader,
                                    httpRequestResponse
                                )
                            )
                        }
                    }
                } else {
                    //Write to persistence storage
                    val headerValueAnalyze: String =
                        httpRequestResponse.response().headerValue(header.headerName)?.toString() ?: "<empty>"
                    addToPersistenceStorage(
                        httpRequestResponse.request().headerValue("Host").toString(),
                        httpRequestResponse.request().path(),
                        httpRequestResponse.response().statusCode(),
                        header.headerName,
                        headerValueAnalyze
                    )
                    if(dataHolder.shouldCreateIssues) {
                        //optimal case
                        if (headerValueAnalyze.lowercase().equals(header.optimalValue.lowercase())) {
                            auditIssueList.add(
                                generatePassedIssue(
                                    header.headerName,
                                    header.optimalValue,
                                    httpRequestResponse,
                                    responseHighlights
                                )
                            )
                        } //Header value is not optimally
                        else {
                            var auditSeverityEmptyHeader = header.getSeverityOfValue(headerValueAnalyze)
                            if (auditSeverityEmptyHeader == AuditIssueSeverity.FALSE_POSITIVE) {
                                var auditSeveritySpecialCase = doSpecialCases(header, headerValueAnalyze)
                                //TODO: Remove false-positive when special cases are finished:
                                // Header has not optimal value but special case is missing so far (therefore severity is currently set to false positive)
                                auditIssueList.add(
                                    generateAuditIssue(
                                        header.headerName,
                                        header.optimalValue,
                                        headerValueAnalyze,
                                        auditSeveritySpecialCase,
                                        httpRequestResponse,
                                        responseHighlights
                                    )
                                )
                            }
                            // Header is set and has severity --> create issue
                            if (auditSeverityEmptyHeader != AuditIssueSeverity.FALSE_POSITIVE) {
                                auditIssueList.add(
                                    generateAuditIssue(
                                        header.headerName,
                                        header.optimalValue,
                                        headerValueAnalyze,
                                        auditSeverityEmptyHeader,
                                        httpRequestResponse,
                                        responseHighlights
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
        return AuditResult.auditResult(auditIssueList)
    }

    override fun consolidateIssues(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction {
        return if (existingIssue.name() == newIssue.name()) ConsolidationAction.KEEP_EXISTING else ConsolidationAction.KEEP_BOTH
    }

    private fun addToPersistenceStorage(
        hostname: String,
        urlpath: String,
        statuscode: Short,
        header: String,
        headerValue: String
    ) {
        if (!header.isEmpty()) {
            val outputLine = listOf(hostname, urlpath, statuscode, header, headerValue)
                .joinToString(CSV_SEPARATOR)
            persistedHeaderList.add(outputLine)
            logger.logToOutput("Added: " + outputLine)
        }
        logger.logToOutput("Current size of persistence list:" + persistedHeaderList.size)
    }

    private fun generatePassedIssue(
        header: String,
        optimalValue: String,
        httpRequestResponse: HttpRequestResponse,
        responseHighlights: MutableList<Marker?>
    ): AuditIssue {
        return AuditIssue.auditIssue(
            header,
            header + " is set optimally.<br/>" + "Value of header is " + optimalValue,
            null,
            httpRequestResponse.request().url(),
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.CERTAIN,
            null,
            null,
            AuditIssueSeverity.INFORMATION,
            httpRequestResponse.withResponseMarkers(responseHighlights)
        )
    }

    private fun generateAuditIssue(
        header: String,
        optimalValue: String,
        currentConfiguration: String,
        severity: AuditIssueSeverity,
        httpRequestResponse: HttpRequestResponse,
        responseHighlights: MutableList<Marker?>
    ): AuditIssue {
        return AuditIssue.auditIssue(
            header,
            header + " is not set optimally.<br/>" + "Value of header is " + currentConfiguration,
            "Better use: " + optimalValue,
            httpRequestResponse.request().url(),
            severity,
            AuditIssueConfidence.CERTAIN,
            null,
            null,
            severity,
            httpRequestResponse.withResponseMarkers(responseHighlights)
        )
    }

    private fun generateAuditIssueNotSet(
        header: String,
        optimalValue: String,
        severity: AuditIssueSeverity,
        httpRequestResponse: HttpRequestResponse
    ): AuditIssue {
        return AuditIssue.auditIssue(
            header,
             header + " is not set",
            "Better use: " + optimalValue,
            httpRequestResponse.request().url(),
            severity,
            AuditIssueConfidence.CERTAIN,
            null,
            null,
            severity,
            httpRequestResponse
        )
    }

    //TODO: finish special cases
    private fun doSpecialCases(header: HeaderSecurityConfig, headerValue: String): AuditIssueSeverity {
        when (header.headerName.lowercase()) {
            "strict-transport-security" -> Unit
            "content-security-policy" -> Unit
            "access-control-allow-origin" -> Unit
            "content-type" -> Unit
            "server", "x-powered-by" -> Unit
            "clear-site-data" -> Unit
            "permissions-policy" -> Unit
            "cache-control" -> return handleCacheControl(header, headerValue)
            else -> logger.logToOutput("Entered special cases but could not match any")
        }
        return AuditIssueSeverity.FALSE_POSITIVE
    }

    private fun handleCacheControl(header: HeaderSecurityConfig, headerValue: String): AuditIssueSeverity {
        var severity: AuditIssueSeverity = AuditIssueSeverity.FALSE_POSITIVE
        val valueLowerCase = headerValue.lowercase()
        if (valueLowerCase.contains(header.optimalValue.lowercase())) {
            severity = AuditIssueSeverity.INFORMATION
        } else if (header.lowValues.any { lowHeaderValue ->
                valueLowerCase.contains(lowHeaderValue.lowercase())
            }) {
            severity = AuditIssueSeverity.LOW
        } else if (header.mediumValues.any { medHeaderValue ->
                valueLowerCase.contains(medHeaderValue.lowercase())
            }) {
            severity = AuditIssueSeverity.MEDIUM
        }
        return severity
    }

    companion object {
        private fun getResponseHighlights(requestResponse: HttpRequestResponse, match: String): MutableList<Marker?> {
            val highlights: MutableList<Marker?> = LinkedList<Marker?>()
            val response = requestResponse.response().toString()
            val responseLowerCase = response.lowercase(Locale.getDefault())
            val matchLowerCase = match.lowercase(Locale.getDefault())
            var start = 0

            while (start < response.length) {
                start = responseLowerCase.indexOf(matchLowerCase, start)
                if (start == -1) {
                    break
                }
                val marker = Marker.marker(start, start + match.length)
                highlights.add(marker)
                start += match.length
            }
            return highlights
        }

        private fun shouldHostBeChecked(request: HttpRequest, hostnameList: List<String>): Boolean {
            val hostname = request.headerValue("Host")
            return hostnameList.contains(hostname)
        }

        private fun configureHeaderScans(stream: InputStream): List<HeaderSecurityConfig> {
            val headerConfigList = ArrayList<HeaderSecurityConfig>()
            stream.bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    headerConfigList.add(HeaderSecurityConfig(line))
                }
            }
            return headerConfigList
        }

        private fun configureHeaderScans(configFilePath: String): List<HeaderSecurityConfig> {
            val headerConfigList = ArrayList<HeaderSecurityConfig>()
            File(configFilePath)
                .useLines { lines ->
                    lines.drop(1).forEach { line ->
                        headerConfigList.add(HeaderSecurityConfig(line))
                    }
                }
            return headerConfigList
        }
    }
}