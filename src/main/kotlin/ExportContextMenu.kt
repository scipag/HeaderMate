import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.io.IOException
import javax.swing.JFileChooser
import javax.swing.JMenuItem

class ExportContextMenu(private val api: MontoyaApi) : ContextMenuItemsProvider {
    private val CSV_SEPARATOR = "\u001F"
    private lateinit var persistedHeaderList: List<String>

    override fun provideMenuItems(event: ContextMenuEvent): MutableList<Component?>? {
        if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.LOGGER)) {
            val menuItemList: MutableList<Component?> = ArrayList<Component?>()
            val retrieveRequestItem = JMenuItem("Export Headers")
            retrieveRequestItem.addActionListener(ActionListener { l: ActionEvent? -> exportData() })
            menuItemList.add(retrieveRequestItem)
            return menuItemList
        }
        return null
    }

    private fun exportData() {
        val titleRow = listOf("hostname", "urlpath", "statuscode", "header", "headervalue")
            .joinToString(CSV_SEPARATOR)
        val persistedStorage = api.persistence().extensionData()
        if (persistedStorage.getStringList(PersistenceConfig.PERSISTED_STORAGE.value)!=null) {
            persistedHeaderList = persistedStorage.getStringList(PersistenceConfig.PERSISTED_STORAGE.value)
            val exportLocation = chooseExportLocation()
            if (exportLocation!!.isEmpty()) {
                api.logging().logToError("Export Location was empty")
            }
            run {
                try {
                    val writer = BufferedWriter(FileWriter(exportLocation + File.separator + "HeaderMateExport.csv"))
                    writer.write(titleRow+ "\n")
                    for(line: String in persistedHeaderList) {
                        writer.write(line + "\n")
                    }
                    writer.flush()
                    api.logging().logToOutput("Finished writing")
                } catch (e: IOException) {
                    api.logging().logToError("Catched: " + e.fillInStackTrace())
                }
            }
        } else {
            api.logging().logToError("Error: persisted storage is empty")
        }
    }

    private fun chooseExportLocation(): String? {
        val chooser = JFileChooser()
        chooser.setDialogTitle("Select Export Location")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        val result = chooser.showOpenDialog(null)
        if (result == JFileChooser.APPROVE_OPTION) {
            val selectedDirectory = chooser.selectedFile
            return selectedDirectory.absolutePath
        } else {
            return null
        }
    }
}