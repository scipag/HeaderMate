import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

class HeaderMate : BurpExtension {
    private lateinit var montoyaApi: MontoyaApi

    override fun initialize(api: MontoyaApi?) {
        montoyaApi = requireNotNull(api) { "api : MontoyaApi is not allowed to be null" }
        montoyaApi.logging().logToOutput("Started loading the extension...")
        montoyaApi.extension().setName("HeaderMate")
        montoyaApi.logging().logToOutput("Greetings from HeaderMate!")
        val dataHolder = DataHolder()
        montoyaApi.scanner().registerScanCheck(HeaderScanCheck(montoyaApi, dataHolder))
        val uiComponent = UIComponent(montoyaApi, dataHolder)
        montoyaApi.userInterface().registerSuiteTab("HeaderMate", uiComponent.getUI())
        montoyaApi.userInterface().registerContextMenuItemsProvider(ExportContextMenu(montoyaApi))
        montoyaApi.logging().logToOutput("...Finished loading the extension")
    }
}