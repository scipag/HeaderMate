import burp.api.montoya.MontoyaApi
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridLayout
import java.io.Serializable
import javax.swing.*

class UIComponent(private val api: MontoyaApi, private val dataHolder: DataHolder) : Serializable{
    val panel: JPanel =  JPanel()

    init {
        panel.layout = BorderLayout(10, 10)
        val titleLabel = JLabel("HeaderMate")
        titleLabel.font = titleLabel.font.deriveFont(Font.BOLD, 18f)
        panel.add(titleLabel, BorderLayout.NORTH)
        val formPanel = JPanel(GridLayout(12, 3, 10, 20))
        val hostnameTextField = JTextField()
        formPanel.add(JLabel("Hostnames to scan:"))
        hostnameTextField.text=dataHolder.hostnames
        formPanel.add(hostnameTextField)
        val checkBoxPanel = JPanel(FlowLayout())
        val createIssuesCheckBox = JCheckBox()
        createIssuesCheckBox.setSelected(dataHolder.shouldCreateIssues)
        checkBoxPanel.add(createIssuesCheckBox)
        checkBoxPanel.add(JLabel("Create issues in Burp"))
        formPanel.add(checkBoxPanel)
        panel.add(formPanel, BorderLayout.CENTER)

        //Config Button
        val bottomPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        val configFileLabel = JLabel("default configuration")
        if(!dataHolder.configFilePath.isEmpty()) {
            configFileLabel.setText(dataHolder.configFilePath)
        }
        val configButton = JButton("Load config file")
        configButton.addActionListener{
            dataHolder.configFilePath=selectConfigFile()
            api.logging().logToOutput("Config file path: " + dataHolder.configFilePath)
            configFileLabel.setText(dataHolder.configFilePath)
            //persist configFilePath
            this.api.persistence().extensionData().setString(PersistenceConfig.PERSISTED_CONFIG_PATH.value, dataHolder.configFilePath)
            dataHolder.hasContentChanged=true
        }

        val saveButton = JButton("Save")
        bottomPanel.add(configFileLabel)
        bottomPanel.add(configButton)
        bottomPanel.add(saveButton)
        panel.add(bottomPanel, BorderLayout.SOUTH)

        saveButton.addActionListener {
            dataHolder.hostnames = hostnameTextField.text
            this.api.persistence().extensionData().setString(PersistenceConfig.PERSISTED_HOSTNAMES.value, dataHolder.hostnames)
            dataHolder.shouldCreateIssues = createIssuesCheckBox.isSelected
            this.api.persistence().extensionData().setBoolean(PersistenceConfig.PERSISTED_CREATE_ISSUES.value, dataHolder.shouldCreateIssues)
            dataHolder.hasContentChanged=true
            api.logging().logToOutput("Saved")
            api.logging().logToOutput("Hostnames to check: " + hostnameTextField.text)
            api.logging().logToOutput("Should Create Issues: " + dataHolder.shouldCreateIssues)
        }
        //set hasContentChanged to true to reload during the initial load of HeaderMate
        dataHolder.hasContentChanged = true
    }

    private fun selectConfigFile(): String {
        val chooser = JFileChooser()
        chooser.setDialogTitle("Select HeaderMate Configuration File")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        val result = chooser.showOpenDialog(null)
        if(result == JFileChooser.APPROVE_OPTION) {
            val selectedConfigfile = chooser.getSelectedFile()
            if (selectedConfigfile.toString().endsWith(".csv")) {
                return selectedConfigfile.absolutePath
            } else {
                api.logging().logToError("Chosen configuration file is not a CSV")
            }
        }
        return ""
    }

    fun getUI(): JPanel {
        return panel
    }
}