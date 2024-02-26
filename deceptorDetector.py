from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditorController
from burp import IContextMenuFactory

from javax.swing import JTextArea, JPopupMenu, JPanel, JLabel, JTextField, JButton, JTable, JScrollPane, JMenuItem, JSplitPane, BoxLayout, JCheckBox, DefaultCellEditor
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from java.awt.event import MouseAdapter, MouseEvent
from java.io import PrintWriter
import java.util.ArrayList
from java.text import SimpleDateFormat
from java.util import Date, Comparator
from java.awt import GridLayout, BorderLayout, FlowLayout, Color

class PlaceholderTextField(JTextField):
    def __init__(self, placeholder, *args):
        super(PlaceholderTextField, self).__init__(*args)
        self.placeholder = placeholder

    def paint(self, g):
        super(PlaceholderTextField, self).paint(g)
        if self.getText().strip() == "":
            g.setColor(Color.GRAY)
            g.drawString(self.placeholder, self.getInsets().left, self.getHeight() / 2 + self.getFont().getSize() / 2 - 1)


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
    def __init__(self):
        # initialize the ID counter for the responses table.
        self.responseId = 0

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
            "tracking_number", "purchase_history", "order_status", "token"
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
        #self.displayKeywordList()  # Display the combined list of keywords
        self._callbacks.addSuiteTab(self)


    def initUI(self):
        self.panel = JPanel(GridLayout(2, 1))

        #JTable for keywords
        keywordsTitleLabel = JLabel("Keywords being searched:")
        keywordsColumnNames = ["Keywords"]
        self.keywordsModel = DefaultTableModel(keywordsColumnNames, 0)
        self.keywordsTable = JTable(self.keywordsModel)
        for keyword in self.sensitiveDataKeywords:
            self.keywordsModel.addRow([keyword])
        keywordsScrollPane = JScrollPane(self.keywordsTable)
        keywordsScrollPane.setPreferredSize(java.awt.Dimension(700, 50))

        # Response Table setup
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

        # Custom keywords input
        placeholderText = "Enter custom keywords (comma-separated, prefix with '-' to remove):"
        self.customKeyTextField = PlaceholderTextField(placeholderText, 20)
        updateButton = JButton('Update', actionPerformed=self.updateKeywords)
        removeButton = JButton('Remove Tested', actionPerformed=self.clearTable)
        clearButton = JButton('Clear Tested List', actionPerformed=self.clearTestedList)
        buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        buttonPanel.add(removeButton)
        buttonPanel.add(clearButton)
        customKeyPanel = JPanel()
        customKeyPanel.setLayout(BoxLayout(customKeyPanel, BoxLayout.X_AXIS))
        customKeyPanel.add(self.customKeyTextField)
        customKeyPanel.add(updateButton)
    
        # JTable for Method/URL
        testedTitleLabel = JLabel("Tested Method/URL:")
        testedColumnNames = ["URL", "Method"]
        self.testedModel = DefaultTableModel(testedColumnNames, 0)
        self.testedTable = JTable(self.testedModel)
        testedScrollPane = JScrollPane(self.testedTable)
        testedScrollPane.setPreferredSize(java.awt.Dimension(700, 180))
        testedTableColumnWidths = [680, 20]
        for i, width in enumerate(testedTableColumnWidths):
            self.testedTable.getColumnModel().getColumn(i).setPreferredWidth(width)
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
        keywordsPanel = JPanel(BorderLayout())
        keywordsLeftPanel = JPanel(BorderLayout())
        keywordsLeftPanel.add(keywordsTitleLabel, BorderLayout.PAGE_START)
        keywordsLeftPanel.add(keywordsScrollPane, BorderLayout.CENTER)
        keywordsLeftPanel.add(customKeyPanel, BorderLayout.PAGE_END)
        keywordsRightPanel = JPanel()
        keywordsRightPanel.setLayout(BoxLayout(keywordsRightPanel, BoxLayout.Y_AXIS))

        keywordsRightPanel.add(testedTitleLabel)
        keywordsRightPanel.add(testedScrollPane)
        keywordsRightPanel.add(buttonPanel)
        keywordsPanel.add(keywordsLeftPanel, BorderLayout.WEST)
        keywordsPanel.add(keywordsRightPanel, BorderLayout.CENTER)

        # Adding components to the panel
        topPanel = JPanel(GridLayout(2, 1))
        topPanel.add(keywordsPanel)
        topPanel.add(scrollPane)

        self.panel.add(topPanel)
        self.panel.add(viewerSplitPane)
        self.table.getModel().addTableModelListener(self.updateTestedTable)

    def updateTestedTable(self, event):
    # Get the row and column that changed
        row = event.getFirstRow()
        column = event.getColumn()

        # If the tested checkmark was clicked
        if column == 0:
            # Get the Method/URL from the row
            method = self.table.getValueAt(row, 3)
            url = self.table.getValueAt(row, 4)

            # If the checkmark is checked, add the Method/URL to the tested table
            if self.table.getValueAt(row, 0):
                for i in range(self.testedModel.getRowCount()):
                    if self.testedModel.getValueAt(i, 0) == url and self.testedModel.getValueAt(i, 1) == method:
                        return
                self.testedModel.addRow([url, method])
                self.testedRequests.add((url, method))
            # Otherwise, remove the Method/URL from the tested table
            else:
                for i in range(self.testedModel.getRowCount()):
                    if self.testedModel.getValueAt(i, 0) == url and self.testedModel.getValueAt(i, 1) == method:
                        self.testedModel.removeRow(i)
                        self.testedRequests.remove((url, method))
                        break

    def updateKeywords(self, event):
    # Get the custom keywords from the text field
        customKeywords = self.customKeyTextField.getText().split(',')

        for keyword in customKeywords:
            # If the keyword starts with '-', remove it from the table and the sensitiveDataKeywords list
            keyword = keyword.strip()
            if keyword.startswith('-'):
                keyword = keyword[1:]
                self._customKeywords.remove(keyword)
                for i in range(self.keywordsModel.getRowCount()):
                    if self.keywordsModel.getValueAt(i, 0) == keyword:
                        self.keywordsModel.removeRow(i)
                        self._stdout.println("Keyword in list: " + keyword)
                        break
            # Otherwise, add the keyword to the table and the sensitiveDataKeywords list
            else:
                self._customKeywords.append(keyword)
                self.keywordsModel.addRow([keyword])

            # Clear the text field
        self.customKeyTextField.setText('')  

    def markDuplicates(self, requestIdentifier, tested=True):
        for i in range(self.table.getRowCount()):
            url = self.table.getValueAt(i, 4)  # Get the URL from column 4
            method = self.table.getValueAt(i, 3)  # Get the method from column 3
            if url == requestIdentifier[0] and method == requestIdentifier[1]:
                self.table.setValueAt(tested, i, 0)  # Mark the row as 'Tested'
                self._stdout.println("Updating duplicate request...")

    def clearTable(self, event):
        new_responses = []
        for i in range(self.model.getRowCount() - 1, -1, -1):
            is_tested = self.model.getValueAt(i, 0)
            if is_tested:
                self.model.removeRow(i)
            else:
                new_responses.append(self._responses[i])
        self._responses = new_responses[::-1]  # Reverse the list to maintain order

    def clearTestedList(self, event):
        self.testedRequests.clear()
        self.testedModel.setRowCount(0)
        self._stdout.println("Tested list cleared.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if the message is a response and in scope
        if not messageIsRequest and self._callbacks.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            requestIdentifier = (str(requestInfo.getUrl()), requestInfo.getMethod())

            # Debugging: Print the request identifier
            self._stdout.println("Processing request: URL = {}, Method = {}".format(requestIdentifier[0], requestIdentifier[1]))

            # Check if the request is already tested
            for request in self.testedRequests:
                if requestIdentifier[0] == request[0] and requestIdentifier[1] == request[1]:
                    self._stdout.println("ALERT: Request already tested, skipping...")
                    return

            self._stdout.println("Request not tested, analyzing response...")
            self.analyzeResponse(messageInfo)

    def analyzeResponse(self, messageInfo):
        response = messageInfo.getResponse()
        analyzedResponse = self._helpers.analyzeResponse(response)
        headers = analyzedResponse.getHeaders()
        responseBody = self._helpers.bytesToString(response)[analyzedResponse.getBodyOffset():]

        # Combine built-in keywords with any custom keywords added by the user
        allKeywords = self._customKeywords
        matchedKeywords = [keyword for keyword in allKeywords if keyword in responseBody]

        # Check for required cache-control headers
        cacheHeaders = ['no-store', 'no-cache', 'must-revalidate', 'Pragma: no-cache', 'Expires: -1']
        isCacheControlPresent = any(any(ch in header for ch in cacheHeaders) for header in headers)

        if matchedKeywords and not isCacheControlPresent:
            tested = False
            httpService = messageInfo.getHttpService()
            requestInfo = self._helpers.analyzeRequest(messageInfo.getRequest())
            url = str(messageInfo.getUrl())  # Directly get the URL from messageInfo
            requestIdentifier = (url, requestInfo.getMethod())
            timestamp = SimpleDateFormat("HH:mm:ss").format(Date())
            self.responseId += 1
            if requestIdentifier in self.testedRequests:
                return
            row_data = [tested, timestamp, self.responseId, requestInfo.getMethod(), url, analyzedResponse.getStatusCode(), len(responseBody), ", ".join(matchedKeywords)]
            self.model.addRow(row_data)
            self._responses.append(messageInfo)
            self._stdout.println("Sensitive response without proper cache control added to table.")
        else:
            self._stdout.println("Response doesn't meet criteria. Not added to table.")

    def getTabCaption(self):
        return "Deceptor Detector"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self):
        menu = java.util.ArrayList()
        menu.add(JMenuItem("Send to Repeater", actionPerformed=lambda x: self.sendToRepeater()))
        menu.add(JMenuItem("Mark as Tested", actionPerformed=lambda x: self.markAsTested()))
        return menu

    def markAsTested(self, messageInfo):
        # Logic to mark a request as tested
        selectedRow = self.table.getSelectedRow()
        if selectedRow == -1:
            return
        self.table.setValueAt(True, selectedRow, 0)
        messageInfo = self._responses[selectedRow]
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        requestIdentifier = (str(requestInfo.getUrl()), requestInfo.getMethod())
        self.testedRequests.add(requestIdentifier)

        self.markDuplicates(requestIdentifier)

    def sendToRepeater(self):
        selectedRow = self.table.getSelectedRow()
        if selectedRow == -1:
            return
        messageInfo = self._responses[selectedRow]
        httpService = messageInfo.getHttpService()
        request = messageInfo.getRequest()

        self._callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), httpService.getProtocol() == "https", request, "Deceptor Detector")

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
                self.markAsTested(messageInfo)
            else:
                self._extender._stdout.println("Error: Row index out of range")
    
    def mouseClicked(self, evt):
        if (evt.getButton() == MouseEvent.BUTTON3):  # Right button clicked
            if self._extender.table.rowAtPoint(evt.getPoint()) != -1:  # Clicked on a row
                # Select the row where right-click occurred
                self._extender.table.setRowSelectionInterval(self._extender.table.rowAtPoint(evt.getPoint()), self._extender.table.rowAtPoint(evt.getPoint()))
                viewRow = self._extender.table.rowAtPoint(evt.getPoint())
                if viewRow != -1:
                    modelRow = self._extender.table.convertRowIndexToModel(viewRow)
                    if modelRow < len(self._extender._responses):
                        messageInfo = self._extender._responses[modelRow]
                        # Create menu
                        menu = self._extender.createMenuItems()
                        # Create popup menu
                        popup = JPopupMenu()
                        for item in menu:
                            popup.add(item)
                        # Show popup menu
                        popup.show(self._extender.table, evt.getX(), evt.getY())
                    else:
                        self._extender._stdout.println("Error: Model row index out of range")
                else:
                    self._extender._stdout.println("Error: View row index out of range")
        else:
            viewRow = self._extender.table.rowAtPoint(evt.getPoint())
            if viewRow != -1:
                modelRow = self._extender.table.convertRowIndexToModel(viewRow)
                if modelRow < len(self._extender._responses):
                    messageInfo = self._extender._responses[modelRow]
                    self._extender.setMessageViewers(messageInfo.getRequest(), messageInfo.getResponse())
                else:
                    self._extender._stdout.println("Error: Row index out of range")
