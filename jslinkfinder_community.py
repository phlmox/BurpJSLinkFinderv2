#
#  BurpLinkFinder Community - Find links within JS files.
#
#  Copyright (c) 2019 Frans Hendrik Botes,
#  Copyright (c) 2024 v2.2 Enes Saltik,
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab,IContextMenuFactory, IHttpRequestResponse
from java.io import PrintWriter
from java.util import ArrayList
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from java.awt import EventQueue,Dimension
from java.lang import Runnable
from javax.swing import JFileChooser, JMenuItem
from javax.swing.table import DefaultTableModel

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js']

class BurpExtender(IBurpExtender, IScannerCheck, ITab,IContextMenuFactory, IHttpRequestResponse):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinder Community")
        callbacks.registerContextMenuFactory(self)

        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        self.blacklist_ext = ["jpg","png","jpeg","gif","css","svg","pdf","woff","woff2","ttf","eot"]
        
        print ("Burp JS LinkFinder V2 loaded.")
        print ("Copyright (c) 2019 Frans Hendrik Botes")
        print ("Copyright (c) 2024 V2.2 (Current) Enes Saltik")
        
    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder V2 Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(142, 68, 173))
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
                )
            )
        )

    def getTabCaption(self):
        return "BurpJSLinkFinder Community"

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

    def createMenuItems(self, invocation):
            items = []
            item = JMenuItem("Run Scan", actionPerformed=lambda _: self.linkfinderWorker(invocation))
            items.append(item)
            return items

    def saveBtn(self,e):
        chooseFile = JFileChooser()
        chooseFile.setDialogTitle('Select Export Location')
        chooseFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        txt=""
        for i in range(self.outputList.getModel().getRowCount()):
            txt+=str(self.outputList.getModel().getValueAt(i,0))+"\t"+self.outputList.getModel().getValueAt(i,1)+"\t"+self.outputList.getModel().getValueAt(i,2)+"\n"
        ret = chooseFile.showSaveDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            if chooseFile.getSelectedFile().isDirectory():
                file_name = str(chooseFile.getSelectedFile())
                f=open(file_name+"/export.txt","w")
                f.write(txt)
                f.close()
            

    def linkfinderWorker(self, invocation):
        messages=invocation.getSelectedMessages()
        for ihrr in messages:
            try:
                urlReq = ihrr.getUrl()
                testString = str(urlReq)
                print("Scanning "+testString)
                linkA = linkAnalyse(ihrr,self.helpers)

                # Exclude casual JS files
                if any(x in testString.split("/")[-1] for x in JSExclusionList):
                    print("[-] URL excluded " + str(urlReq))
                else:
                    issueText = linkA.analyseURL()
                    for counter, issueText in enumerate(issueText):
                            if "." in issueText['link']:
                                if issueText['link'].split("?")[0].split(".")[-1] in self.blacklist_ext:
                                    continue
                            self.outputList.getModel().addRow([self.outputList.getModel().getRowCount(),str(urlReq),issueText['link']])
            except UnicodeEncodeError:
                print ("Error in URL decode.")
        print("Scan ended.")
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print("BurpJSLinkFinder Community unloaded")
        return

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = r"""

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
    [a-zA-Z0-9_\-/.]{1,}                # Resource name
    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    |

    ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    |

    ([a-zA-Z0-9_\-]{1,}                 # filename
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)        # . + extension
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

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
        encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
        decoded_resp=base64.b64decode(encoded_resp)
        endpoints=self.parser_file(decoded_resp, self.regex_str)
        return endpoints
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
