enum class HeaderConfig(val value: String) {
    EMPTY("<empty>"),
    NONE("<none>"),
    MIMETYPE_CHARSET_SET("<mimetype_charset_set>"),
    CHARSET_EMPTY_NOT_HTML("<charset_empty_not_html>"),
    CHARSET_EMPTY_AND_HTML("<charset_empty_and_html"),
    VALUE_SET("<value_set>"),
    VALUE_WITH_VERSION("<value_with_version>"),
    FEATURE_POLICY_SET("<feature_policy_set>"),
    PERMISSION_POLICY_SET_EMPTY("<permissions_policy_set_empty>"),
    MAX_AGE_1YEAR("<max-age_1year>");

    companion object {
        fun isSpecialValue(value: String): Boolean{
            return (value.startsWith("<") && value.endsWith(">"))
        }
    }
}