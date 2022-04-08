#
#  BurpLinkFinder - Find links within JS files.
#
#  Copyright (c) 2019 Frans Hendrik Botes,
#  Copyright (c) 2022 v2.1 Enes Saltik,
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue,Dimension
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser
from javax.swing.table import DefaultTableModel

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js']

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinder")
        callbacks.issueAlert("BurpJSLinkFinder Passive Scanner enabled")

        self.onlyScope = False

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        self.blacklist_ext = ["jpg","png","jpeg","gif","css","svg","pdf","woff","woff2","ttf","eot"]
        
        print ("Burp JS LinkFinder V2 loaded.")
        print ("Copyright (c) 2019 Frans Hendrik Botes")
        print ("Copyright (c) 2022 V2.1 (Current) Enes Saltik")
        
    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder V2 Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.tableData = []
        colNames = ('ID','URL','Path')
        self.dataModel = DefaultTableModel(self.tableData, colNames)
        self.outputList = swing.JTable(self.dataModel)
        self.outputList.setAutoCreateRowSorter(True)
        self.scrollPane = swing.JScrollPane()
        self.scrollPane.setPreferredSize(Dimension(300,100))
        self.scrollPane.getViewport().setView((self.outputList))

        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.DeleteSelectedBtn = swing.JButton("Delete Selected Items", actionPerformed=self.deleteSelected)
        self.exportBtn = swing.JButton("Save Endpoints", actionPerformed=self.saveBtn)

        self.onlyScopeCheckbox = swing.JCheckBox("Only Scope",actionPerformed=self.checkBoxScope)

        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.scrollPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.DeleteSelectedBtn)
                    .addComponent(self.exportBtn)
                    .addComponent(self.onlyScopeCheckbox)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.scrollPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.DeleteSelectedBtn)
                    .addComponent(self.exportBtn)
                    .addComponent(self.onlyScopeCheckbox)
                )
            )
        )

    def checkBoxScope(self,_x):
        if self.onlyScope:
            self.onlyScope =False
        else:
            self.onlyScope =True


    def getTabCaption(self):
        return "BurpJSLinkFinder"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
        self.dataModel.setRowCount(0)
    
    def deleteSelected(self, event):
        selected = self.outputList.getSelectedRows()
        Idel=0
        for i in selected:
            self.outputList.getModel().removeRow(i-Idel)
            Idel+=1

    def saveBtn(self,e):
        chooseFile = JFileChooser()
        chooseFile.setDialogTitle('Select Export Location')
        chooseFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        txt=""
        for i in range(self.outputList.getModel().getRowCount()):
            txt+=str(self.outputList.getModel().getValueAt(i,0))+"\t"+self.outputList.getModel().getValueAt(i,1)+"\n"
        ret = chooseFile.showSaveDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            if chooseFile.getSelectedFile().isDirectory():
                file_name = str(chooseFile.getSelectedFile())
                f=open(file_name+"/export.txt","w")
                f.write(txt)
                f.close()
            

    def doPassiveScan(self, ihrr):
        
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            linkA = linkAnalyse(ihrr,self.helpers)
            # check if JS file
            if ".js" in str(urlReq):
                # Exclude casual JS files
                if any(x in testString.split("/")[-1] for x in JSExclusionList):
                    print("\n" + "[-] URL excluded " + str(urlReq))
                else:
                    if self.onlyScope and not self.callbacks.isInScope(urlReq):
                        return
                    issueText = linkA.analyseURL()
                    for counter, issueText in enumerate(issueText):
                            if "." in issueText['link']:
                                if issueText['link'].split("?")[0].split(".")[-1] in self.blacklist_ext:
                                    continue
                            self.outputList.getModel().addRow([self.outputList.getModel().getRowCount(),str(urlReq),issueText['link']])
                    issues = ArrayList()
                    issues.add(SRI(ihrr, self.helpers))
                    return issues
        except UnicodeEncodeError:
            print ("Error in URL decode.")
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print "Burp JS LinkFinder unloaded"
        return

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = """
    
      (?:"|')                               # Start newline delimiter
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    
        |
    
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    
        |
    
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
    
      )
    
      (?:"|')                               # End newline delimiter
    
    """     

    def	parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items
    
        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):
        endpoints = ""
        mime_type=self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
                url = self.reqres.getUrl()
                encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
                decoded_resp=base64.b64decode(encoded_resp)
                endpoints=self.parser_file(decoded_resp, self.regex_str)
                return endpoints
        return endpoints


class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following JS file for links: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
