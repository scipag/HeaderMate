class DataHolder {
    var hostnames: String = ""
        get() {
            return field
        }
        set(value) {
            field = value
        }

    var configFilePath: String = ""
        get() {return field}
        set(value) {
            field = value
        }

    var shouldCreateIssues: Boolean = true
        get() {return field}
        set(value) {
            field = value
        }

    var hasContentChanged: Boolean = false
        get() {return field}
        set(value) {
            field = value
        }
}