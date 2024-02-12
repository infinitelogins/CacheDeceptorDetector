from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditorController
from burp import IContextMenuFactory

from javax.swing import event, JPanel, JLabel, JTextField, JButton, JTable, JScrollPane, JMenuItem, JSplitPane, BoxLayout, JCheckBox, DefaultCellEditor
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from java.awt.event import MouseAdapter, MouseEvent
from java.io import PrintWriter
import java.util.ArrayList
from java.text import SimpleDateFormat
from java.util import Date, Comparator
from javax.swing import JTextArea
from javax.swing import SwingUtilities
from java.awt import BorderLayout, GridLayout, FlowLayout
from java.lang import Boolean

class CheckBoxRenderer(DefaultTableCellRenderer):
    def __init__(self):
        self.checkbox = JCheckBox()
        self.checkbox.setHorizontalAlignment(JCheckBox.CENTER)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        self.checkbox.setSelected(value)
        return self.checkbox

class LogTableModel(DefaultTableModel):
    def __init__(self, columnNames, rows):
        DefaultTableModel.__init__(self, columnNames, rows)

    def isCellEditable(self, row, column):
        if column == 0:
            return True
        return False

class IntegerComparator(Comparator):
    def compare(self, o1, o2):
        return int(o1) - int(o2)

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self.testedRequests = set()
        self._responses = [] 


        # Define the sensitiveDataKeywords list
        self.sensitiveDataKeywords = [
            "username", "password", "email", "credit_card", "card_expiry", "cvv",
            "phone_number", "address", "date_of_birth", "social_security_number",
            "passport_number", "driver_license", "account_number", "user_id",
            "session_token", "auth_token", "pin", "security_question",
            "security_answer", "transaction_id", "order_id", "payment_method",
            "billing_address", "shipping_address", "order_total",
            "tracking_number", "purchase_history", "order_status"
        ]

        # Initialize customKeywords if not already done
        self._customKeywords = []

        # Combine built-in and custom keywords
        for keyword in self.sensitiveDataKeywords:
            if keyword not in self._customKeywords:
                self._customKeywords.append(keyword)

        self._callbacks.setExtensionName("Cache Issue Detector")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

        # Create UI components
        self.initUI()
        self.displayKeywordList()  # Display the combined list of keywords
        self._callbacks.addSuiteTab(self)


    def initUI(self):
        self.panel = JPanel(GridLayout(2, 1))

        # JTextArea for keywords
        keywordsTitleLabel = JLabel("Keywords being searched:")
        self.keywordsTextArea = JTextArea()
        self.keywordsTextArea.setLineWrap(True)
        self.keywordsTextArea.setWrapStyleWord(True)
        self.keywordsTextArea.setEditable(False)
        self.keywordsTextArea.setRows(2)
        keywordsScrollPane = JScrollPane(self.keywordsTextArea)
        keywordsScrollPane.setPreferredSize(java.awt.Dimension(700, 50))

        # Table setup
        responseColumnNames = ["Tested", "Timestamp", "ID", "Method", "URL", "Status", "Length", "Trigger Keyword"]
        self.model = LogTableModel(responseColumnNames, 0)
        self.table = JTable(self.model)
        sorter = TableRowSorter(self.model)
        sorter.setComparator(1, IntegerComparator())
        self.table.setRowSorter(sorter)
        self.table.addMouseListener(TableClickListener(self))
        scrollPane = JScrollPane(self.table)
        scrollPane.setPreferredSize(java.awt.Dimension(700, 200))
        
        # Create a checkbox and use it as a cell renderer and editor for the first column
        checkbox = JCheckBox()
        checkbox.setHorizontalAlignment(JCheckBox.LEFT)
        renderer = DefaultTableCellRenderer()
        # Create a checkbox renderer and use it for the first column
        renderer = CheckBoxRenderer()
        self.table.getColumnModel().getColumn(0).setCellRenderer(renderer)

        # Create a checkbox editor and use it for the first column
        editor = DefaultCellEditor(JCheckBox())
        self.table.getColumnModel().getColumn(0).setCellEditor(editor)

        columnWidths = [10, 40, 20, 20, 700, 20, 20, 400]
        for i, width in enumerate(columnWidths):
            self.table.getColumnModel().getColumn(i).setPreferredWidth(width)

        # Other UI components
        customKeyLabel = JLabel("Enter custom keywords (comma-separated, prefix with '-' to remove):")
        self.textField = JTextField(20)
        updateButton = JButton('Update', actionPerformed=self.updateKeywords)
        clearButton = JButton('Clear Tested', actionPerformed=self.clearTable)
        #markAsTestedButton = JButton('Mark as Tested', actionPerformed=self.onMarkAsTested)
        buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        buttonPanel.add(updateButton)
        buttonPanel.add(clearButton)
        #buttonPanel.add(markAsTestedButton)
    
        # Request/Response Viewer
        self.requestViewer = self._callbacks.createMessageEditor(self, False)
        self.responseViewer = self._callbacks.createMessageEditor(self, False)

        # Set minimum sizes
        self.requestViewer.getComponent().setMinimumSize(java.awt.Dimension(350, 150))
        self.responseViewer.getComponent().setMinimumSize(java.awt.Dimension(350, 150))

        viewerSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.requestViewer.getComponent(), self.responseViewer.getComponent())
        viewerSplitPane.setResizeWeight(0.5)

        # Add the split pane to the parent container
        viewerSplitPane.setPreferredSize(java.awt.Dimension(700, 300))
        keywordsPanel = JPanel(GridLayout(1, 2))
        keywordsLeftPanel = JPanel()
        keywordsLeftPanel.setLayout(BoxLayout(keywordsLeftPanel, BoxLayout.Y_AXIS))

        keywordsLeftPanel.add(keywordsTitleLabel)
        keywordsLeftPanel.add(keywordsScrollPane)
        keywordsRightPanel = JPanel()
        keywordsRightPanel.setLayout(BoxLayout(keywordsRightPanel, BoxLayout.Y_AXIS))

        keywordsRightPanel.add(customKeyLabel)
        keywordsRightPanel.add(self.textField)
        keywordsRightPanel.add(buttonPanel)
        keywordsPanel.add(keywordsLeftPanel)
        keywordsPanel.add(keywordsRightPanel)

        # Adding components to the panel
        topPanel = JPanel(GridLayout(2, 1))
        topPanel.add(keywordsPanel)
        topPanel.add(scrollPane)

        self.panel.add(topPanel)
        self.panel.add(viewerSplitPane)

    def updateKeywords(self, event):
        keywords = self.textField.getText().strip()
        if keywords:
            if keywords.startswith('-'):
                # Removal of keyword
                keywordToRemove = keywords[1:].strip()
                if keywordToRemove in self._customKeywords:
                    self._customKeywords.remove(keywordToRemove)
                else:
                    self._stdout.println("Keyword not in list: " + keywordToRemove)
            else:
                # Addition of new keywords
                new_keywords = [keyword.strip() for keyword in keywords.split(',') if keyword.strip()]
                for keyword in new_keywords:
                    if keyword not in self._customKeywords:
                        self._customKeywords.append(keyword)
        self.displayKeywordList()  # Update the displayed keyword list

    def displayKeywordList(self):
        self.keywordsTextArea.setText(", ".join(self._customKeywords))

    def clearTable(self, event):
        new_responses = []
        for i in range(self.model.getRowCount() - 1, -1, -1):
            is_tested = self.model.getValueAt(i, 0)
            if is_tested:
                self.model.removeRow(i)
            else:
                new_responses.append(self._responses[i])
        self._responses = new_responses[::-1]  # Reverse the list to maintain order


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if the message is a response and in scope
        if not messageIsRequest and self._callbacks.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            requestIdentifier = (str(requestInfo.getUrl()), requestInfo.getMethod())

            # Debugging: Print the request identifier
            self._stdout.println("Processing request: URL = {}, Method = {}".format(requestIdentifier[0], requestIdentifier[1]))

            # Check if the request is already tested
            if requestIdentifier not in self.testedRequests:
                self._stdout.println("Request not tested, analyzing response...")
                self.analyzeResponse(messageInfo)
            else:
                self._stdout.println("Request already tested, skipping...")


    def onCheckboxChanged(self, event):
        # Logic to update self.testedRequests based on checkbox state
        row = event.getFirstRow()
        tested = self.model.getValueAt(row, 0)  # Get checkbox state
        url = self.model.getValueAt(row, 4)     # URL
        method = self.model.getValueAt(row, 3)  # Method
        requestIdentifier = (url, method)
        if tested:
            self.testedRequests.add(requestIdentifier)
        else:
            self.testedRequests.remove(requestIdentifier)

    def analyzeResponse(self, messageInfo):
        response = messageInfo.getResponse()
        analyzedResponse = self._helpers.analyzeResponse(response)
        headers = analyzedResponse.getHeaders()
        responseBody = self._helpers.bytesToString(response)[analyzedResponse.getBodyOffset():]

        # Combine built-in keywords with any custom keywords added by the user
        allKeywords = self.sensitiveDataKeywords + self._customKeywords
        matchedKeywords = [keyword for keyword in allKeywords if keyword in responseBody]

        # Check for required cache-control headers
        cacheHeaders = ['no-store', 'no-cache', 'must-revalidate', 'Pragma: no-cache', 'Expires: -1']
        isCacheControlPresent = any(any(ch in header for ch in cacheHeaders) for header in headers)

        if matchedKeywords and not isCacheControlPresent:
            httpService = messageInfo.getHttpService()
            requestInfo = self._helpers.analyzeRequest(messageInfo.getRequest())
            url = messageInfo.getUrl().toString()  # Directly get the URL from messageInfo

            timestamp = SimpleDateFormat("HH:mm:ss").format(Date())
            responseId = len(self._responses) + 1
            row_data = [False, timestamp, responseId, requestInfo.getMethod(), url, analyzedResponse.getStatusCode(), len(responseBody), ", ".join(matchedKeywords)]
            self.model.addRow(row_data)
            self._responses.append(messageInfo)
            self._stdout.println("Sensitive response without proper cache control added to table.")
        else:
            self._stdout.println("Response doesn't meet criteria. Not added to table.")


    def getTabCaption(self):
        return "Deceptor Detector"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = java.util.ArrayList()
        menu.add(JMenuItem("Send to Repeater", actionPerformed=lambda x: self.sendToRepeater(invocation)))
        menu.add(JMenuItem("Mark as Tested", actionPerformed=lambda x: self.markAsTested(invocation.getSelectedMessages()[0])))
        return menu

    def markAsTested(self, messageInfo):
        # Logic to mark a request as tested
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        self.testedRequests.add((str(requestInfo.getUrl()), requestInfo.getMethod()))
        url = messageInfo.getUrl().toString()

        for i in range(self.model.getRowCount()):
            if self.model.getValueAt(i, 4) == url:
                self.model.setValueAt(True, i, 0)

    def sendToRepeater(self, invocation):
        selectedRow = self.table.getSelectedRow()
        if selectedRow == -1:
            return

        messageInfo = self._responses.get(selectedRow)
        httpService = messageInfo.getHttpService()
        request = messageInfo.getRequest()

        self._callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), httpService.getProtocol() == "https", request, "Deceptor Detector")

    def onMarkAsTested(self, event):
        selectedRow = self.table.getSelectedRow()
        if selectedRow != -1:
            self.model.setValueAt(True, selectedRow, 0)  # Set the 'Tested' column to True
            messageInfo = self._responses[selectedRow]
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            self.testedRequests.add((str(requestInfo.getUrl()), requestInfo.getMethod()))
            url = str(messageInfo.getUrl())
            for i in range(self.model.getRowCount()):
                if self.model.getValueAt(i, 4) == url:
                    self.model.setValueAt(True, i, 0)

    def getHttpService(self):
        return self.currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self.currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self.currentlyDisplayedItem.getResponse()

    def setMessageViewers(self, request, response):
        self.requestViewer.setMessage(request, True)
        self.responseViewer.setMessage(response, False)

class TableClickListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def tableChanged(self, evt):
        if evt.getColumn() == 0:
            row = evt.getFirstRow()
            modelRow = self._extender.table.convertRowIndexToModel(row)
            if modelRow < len(self._extender._responses):
                messageInfo = self._extender._responses[modelRow]
                self.self.markAsTested(messageInfo)
            else:
                self._extender._stdout.println("Error: Row index out of range")
    def mouseClicked(self, evt):
        viewRow = self._extender.table.rowAtPoint(evt.getPoint())
        if viewRow != -1:
            modelRow = self._extender.table.convertRowIndexToModel(viewRow)
            if modelRow < len(self._extender._responses):
                messageInfo = self._extender._responses[modelRow]
                self._extender.setMessageViewers(messageInfo.getRequest(), messageInfo.getResponse())
            else:
                self._extender._stdout.println("Error: Row index out of range")
