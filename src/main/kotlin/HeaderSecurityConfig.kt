import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

class HeaderSecurityConfig(headerConfigLine: String) {
    var headerName: String
    var optimalValue: String
    var passedValues: List<String>
    var lowValues: List<String>
    var mediumValues: List<String>

    init {
        val headerConfigList = headerConfigLine.split("#")
        //Item 0 is checklistID
        headerName = headerConfigList.get(1).toString()
        optimalValue = headerConfigList.get(2).toString()
        passedValues = splitConfigItem(headerConfigList.get(3).toString())
        lowValues = splitConfigItem(headerConfigList.get(4).toString())
        mediumValues = splitConfigItem(headerConfigList.get(5).toString())
    }

    private fun splitConfigItem(configItem: String): List<String> {
        val splittedConfigItem: List<String>
        if(configItem.contains("|")) {
            splittedConfigItem = configItem.split("|")
        } else{
            splittedConfigItem = ArrayList<String>()
            splittedConfigItem.add(configItem)
        }
        return splittedConfigItem
    }

    fun getSeverityOfValue(headerValue: String): AuditIssueSeverity {
        var auditSeverity: AuditIssueSeverity = AuditIssueSeverity.FALSE_POSITIVE
        if (optimalValue.lowercase().equals(headerValue.lowercase()) || passedValues.containsIgnoreCase(headerValue)) {
            auditSeverity = AuditIssueSeverity.INFORMATION
        } else if (lowValues.containsIgnoreCase(headerValue)) {
            auditSeverity = AuditIssueSeverity.LOW
        } else if (mediumValues.containsIgnoreCase(headerValue)) {
            auditSeverity = AuditIssueSeverity.MEDIUM
        }
        return auditSeverity
    }

    private fun List<String>.containsIgnoreCase(value: String): Boolean {
        return this.any { it.equals(value, ignoreCase = true) }
    }
}