"""
Name:           SQLiPy
Version:        0.8.0
Date:           9/3/2014
Author:         Josh Berry - josh.berry@codewatch.org
Github:         https://github.com/codewatchorg/sqlipy

Description:    This plugin leverages the SQLMap API to initiate SQLMap scans against the target.

This plugin requires the beta version of Jython as it uses the JSON module.

I used this blog post to quickly understand and leverage the SQLMap API (thrilled that someone figured this out for me):
http://volatile-minds.blogspot.com/2013/04/unofficial-sqlmap-restful-api.html

The following Burp plugins were reviewed to help develop this:
- Payload Parser: https://github.com/infodel
- Burp SAMl: https://github.com/Meatballs1/burp_saml
- ActiveScan++:
- WCF Binary SOAP Handler: http://blog.securityps.com/2013/02/burp-suite-plugin-view-and-modify-wcf.html
- WSDL Wizard: https://github.com/SmeegeSec/WSDLWizard/blob/master/WSDLWizard.py
- co2: https://code.google.com/p/burp-co2/

"""

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IHttpRequestResponse
from burp import IMessageEditorController
from burp import IMessageEditorTabFactory
from burp import ITab
from burp import IMessageEditorTab
from burp import IScannerCheck
from burp import IScanIssue
from burp import IExtensionStateListener
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import GridBagLayout
from java.awt import Font
from java.awt import Color
from java import awt
from java.lang import Runtime
from java.lang import Process
from java.lang import System
from java.lang import Runnable
from java.lang import Thread
from java.io import File
from java.io import Reader
from java.io import BufferedReader
from java.io import InputStreamReader
import subprocess
import re
import urllib2
import sys
import json
import threading
import time
import zipfile
import os

class StreamGobbler(Runnable):

    def __init__(self, inStream, outStream):
        self.inStream = inStream
        self.outStream = outStream
        return

    def run(self):
        try:
            while (self.inStream.read() != -1):
                isr = InputStreamReader(self.inStream)
                br = BufferedReader(isr)
                print str(br.readLine())

        except BaseException as ex:
            print 'Could not read API input/output/error buffer\n'

class SqlMapScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.vulnurl = url
        self.HttpMessages = httpMessages
        self.vulnname = name
        self.vulndetail = detail
        self.vulnsev = severity
        self.vulnconf = confidence
        return

    def getUrl(self):
        return self.vulnurl

    def getIssueName(self):
        return self.vulnname

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.vulnsev

    def getConfidence(self):
        return self.vulnconf

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.vulndetail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService

class ThreadExtender(IBurpExtender, IContextMenuFactory, ITab, IScannerCheck):
  def __init__(self, burpobject, sqlmapip, sqlmapport, sqlmaptask, url, httpmessage, cbacks):
    self.burpobject = burpobject
    self.sqlmapip = sqlmapip
    self.sqlmapport = sqlmapport
    self.sqlmaptask = sqlmaptask
    self.url = url
    self.httpmessage = httpmessage
    self.cbacks = cbacks

  def checkResults(self):
    t = threading.currentThread()
    time.sleep(5)
    print 'Checking results on task: '+self.sqlmaptask+'\n'

    while getattr(t, "keep_running", True):

      try:
        req = urllib2.Request('http://' + self.sqlmapip + ':' + self.sqlmapport + '/scan/' + self.sqlmaptask + '/status')
        req.add_header('Content-Type', 'application/json')
        resp = json.load(urllib2.urlopen(req, timeout=10))

        if resp['status'] == "running":
          print 'Scan for task '+self.sqlmaptask+' is still running.\n'
          time.sleep(30)
        elif resp['status'] == "terminated":
          if resp['returncode'] == 0:
            print 'Scan for task '+self.sqlmaptask+' completed.  Gathering results.\n'
            vulnurl = ''
            vulnparam = ''
            dbtype = ''
            payloads = ''
            banner = ''
            cu = ''
            cdb = ''
            hostname = ''
            isdba = ''
            lusers = ''
            lprivs = ''
            lroles = ''
            ldbs = ''
            lpswds = ''

            try:
              req = urllib2.Request('http://' + self.sqlmapip + ':' + self.sqlmapport + '/scan/' + self.sqlmaptask + '/data')
              req.add_header('Content-Type', 'application/json')
              resp = json.load(urllib2.urlopen(req, timeout=10))
              vulnerable = False

              for findings in resp['data']:
                vulnerable = True

                # Get vulnerable URL and param
                if findings['type'] == 0:
                  vulnurl = findings['value']['url']
                  vulnparam = findings['value']['query']
                  vulndetails = '<ul><li>URL: '+str(vulnurl)+'</li><li>Parameter: '+str(vulnparam)+'</li></ul>'

                # Get basic scan info
                if findings['type'] == 1:
                  if isinstance(findings['value'][0]['dbms'], list):
                    for dbtypes in findings['value'][0]['dbms']:
                      dbtype = dbtype + dbtypes + ', or '

                    dbtype = dbtype[:-5]
                  else:
                    dbtype = findings['value'][0]['dbms']

                  for items in findings['value']:
                    firstpayload = True
                    for k in items['data']:
                      if firstpayload:
                        payloads = '<li>'+items['data'][k]['payload']+'</li>'
                        firstpayload = False
                      else:
                        payloads = payloads + '<li>'+items['data'][k]['payload']+'</li>'

                    if firstpayload == False:
                      payloads = '<ul>' + payloads + '</ul><BR>'

                # Get banner info
                if findings['type'] == 3:
                  banner = findings['value']+'<BR>'

                # Get Current Users
                elif findings['type'] == 4:
                  cu = 'Current User: '+findings['value']+'<BR>'

                # Get Current Database
                elif findings['type'] == 5:
                  cdb = 'Current Database: '+findings['value']+'<BR>'

                # Get Hostname
                elif findings['type'] == 6:
                  if findings['value'] is not None: 
                    hostname = 'Hostname: '+str(findings['value'])+'<BR>' 
                  else: 
                    hostname = 'Hostname: Enumeration failed.<BR>' 


                # Is the user a DBA?
                elif findings['type'] == 7:
                  if findings['value'] == True:
                    isdba = 'Is a DBA: Yes'+'<BR>'
                  else:
                    isdba = 'Is a DBA: No'+'<BR>'

                # Get list of users
                elif findings['type'] == 8:
                  firstuser = True
                  for user in findings['value']:
                    if firstuser:
                      lusers = '<li>'+user+'</li>'
                      firstuser = False
                    else:
                      lusers = lusers + '<li>'+user+'</li>'

                  if firstuser == False:
                    lusers = 'Users:<ul>' + lusers + '</ul><BR>'

                # Get list of passwords
                elif findings['type'] == 9:
                  userdata = ''
                  userpswds = ''
                  firstuser = True

                  for users in findings['value']:
                    firstpswd = True

                    if firstuser:
                      firstuser = False
                      userdata = '<li>'+users+'</li>'
                    else:
                      userdata = userdata + '<li>'+users+'</li>'

                    for pswd in findings['value'][users]:
                      if firstpswd:
                        firstswd = False
                        userpswds = '<li>'+pswd+'</li>'
                      else:
                        userpswds = userpswds + '<li>'+pswd+'</li>'

                    lpswds = lpswds + userdata + '<ul>'+userpswds+'</ul>'
                    userdata = ''
                    userpswds = ''

                  if firstuser == False:
                    lpswds = 'Password Hashes per User:<ul>'+lpswds+'</ul><BR>'

                # Get list of privileges
                elif findings['type'] == 10:
                  userdata = ''
                  userprivs = ''
                  firstuser = True

                  for users in findings['value']:
                    firstpriv = True

                    if firstuser:
                      firstuser = False
                      userdata = '<li>'+users+'</li>'
                    else:
                      userdata = userdata + '<li>'+users+'</li>'

                    if findings['value'][users] is not None:
                      for priv in findings['value'][users]:
                        if firstpriv:
                          firstpriv = False
                          userprivs = '<li>'+priv+'</li>'
                        else:
                          userprivs = userprivs + '<li>'+priv+'</li>'
                    else:
                      userprivs = '<li>Null</li>'

                    lprivs = lprivs + userdata + '<ul>'+userprivs+'</ul>'
                    userdata = ''
                    userprivs = ''

                  if firstuser == False:
                    lprivs = 'Privileges per User:<ul>'+lprivs+'</ul><BR>'

                # Get list of roles
                elif findings['type'] == 11:
                  userdata = ''
                  userroles = ''
                  firstuser = True

                  for users in findings['value']:
                    firstrole = True

                    if firstuser:
                      firstuser = False
                      userdata = '<li>'+users+'</li>'
                    else:
                      userdata = userdata + '<li>'+users+'</li>'

                    if findings['value'][users] is not None:
                      for role in findings['value'][users]:
                        if firstrole:
                          firstrole = False
                          userroles = '<li>'+role+'</li>'
                        else:
                          userroles = userroles + '<li>'+role+'</li>'
                    else:
                      userroles = '<li>Null</li>'

                    lroles = lroles + userdata + '<ul>'+userroles+'</ul>'
                    userdata = ''
                    userroles = ''

                  if firstuser == False:
                    lroles = 'Roles per User:<ul>'+lroles+'</ul><BR>'

                # Get list of DBs
                elif findings['type'] == 12:
                  firstdb = True
                  for db in findings['value']:
                    if firstdb:
                      ldbs = '<li>'+str(db)+'</li>'
                      firstdb = False
                    else:
                      ldbs = ldbs + '<li>'+str(db)+'</li>'

                  if firstdb == False:
                    ldbs = 'Databases:<ul>' + ldbs + '</ul><BR>'

              if vulnerable:
                if re.search('Free', self.cbacks.getBurpVersion()[0], re.IGNORECASE) is not None:
                  findings = open(self.sqlmaptask + '.html', 'w')
                  findings.write('<html><head><title>SQLMap Scan - ' + self.sqlmaptask + '</title></head><body>')
                  findings.write('<h1>SQLMap Scan Finding</h1><br><p>The application has been found to be vulnerable to SQL injection by SQLMap.</p><br>')
                  findings.write('<p>Vulnerable URL and Parameter:</p><p>'+vulndetails+'</p>')
                  findings.write('<p>The following payloads successfully identified SQL injection vulnerabilities:</p><p>'+payloads+'</p><p>Enumerated Data:</p><BR><p>'+dbtype+': '+banner+'</p><p>'+cu+'</p><p>'+cdb+'</p><p>'+hostname+'</p><p>'+isdba+'</p><p>'+lusers+'</p><p>'+lpswds+'</p><p>'+lprivs+'</p><p>'+lroles+'</p><p>'+ldbs+'</p>')
                  findings.write('</body></html>')
                  findings.close()
                  print 'Wrote scan file ' + self.sqlmaptask + '.html\n'
                else:
                  scanIssue = SqlMapScanIssue(self.httpmessage.getHttpService(), self.url, [self.httpmessage], 'SQLMap Scan Finding',
                      'The application has been found to be vulnerable to SQL injection by SQLMap.  <BR><BR>Vulnerable URL and Parameter:<p>'+vulndetails+'</p><BR>The following payloads successfully identified SQL injection vulnerabilities:<p>'+payloads+'</p><p>Enumerated Data:</p><BR><p>'+dbtype+': '+banner+'</p><p>'+cu+'</p><p>'+cdb+'</p><p>'+hostname+'</p><p>'+isdba+'</p><p>'+lusers+'</p><p>'+lpswds+'</p><p>'+lprivs+'</p><p>'+lroles+'</p><p>'+ldbs+'</p>', 'Certain', 'High')
                  self.cbacks.addScanIssue(scanIssue)

                print 'SQLi vulnerabilities were found for task '+self.sqlmaptask+' and have been reported.\n'
              else:
                print 'Scan completed for task '+self.sqlmaptask+' but SQLi vulnerabilities were not found.\n'

              break

            except:
              print 'No results for SQLMap task: '+self.sqlmaptask+'\n'
              break

          else:
            print 'SQLMap scan failed for task: '+self.sqlmaptask+'\n'
            break

        else:
          print 'SQLMap scan failed for task: '+self.sqlmaptask+'\n'
          break

      except:
        print 'Thread failed to get results for SQLMap task: ' + self.sqlmaptask+'\n'
        break

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
  pythonfile = ''
  apifile = ''
  apiprocess = Process
  apistatus = 0
  threads = []
  scanMessage = ''
  scantasks = []
  scancmds = {}

  # Implement IBurpExtender
  def registerExtenderCallbacks(self, callbacks):
    # Print information about the plugin, set extension name, setup basic stuff
    self.printHeader()
    callbacks.setExtensionName("SQLiPy Sqlmap Integration")
    callbacks.registerExtensionStateListener(self)
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.registerContextMenuFactory(self)

    # Create SQLMap API configuration JPanel
    self._jPanel = swing.JPanel()
    self._jPanel.setLayout(awt.GridBagLayout())
    self._jPanelConstraints = awt.GridBagConstraints()

    # Create first blank space
    self._jLabelAPISpace1 = swing.JLabel(" ")
    self._jLabelAPISpace1.setFont(Font("Courier New", Font.BOLD, 30))
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 2
    self._jPanelConstraints.gridwidth = 2
    self._jPanel.add(self._jLabelAPISpace1, self._jPanelConstraints)

    # Create second blank space
    self._jLabelAPISpace2 = swing.JLabel(" ")
    self._jLabelAPISpace2.setFont(Font("Courier New", Font.BOLD, 30))
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 3
    self._jPanelConstraints.gridwidth = 2
    self._jPanel.add(self._jLabelAPISpace2, self._jPanelConstraints)

    # Create panel to show API status
    self._jLabelAPIStatus = swing.JLabel("SQLMap API is NOT running!")
    self._jLabelAPIStatus.setFont(Font("Courier New", Font.BOLD, 24))
    self._jLabelAPIStatus.setForeground(Color.RED)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 4
    self._jPanelConstraints.gridwidth = 2
    self._jPanel.add(self._jLabelAPIStatus, self._jPanelConstraints)

    # Create third blank space
    self._jLabelAPISpace3 = swing.JLabel(" ")
    self._jLabelAPISpace3.setFont(Font("Courier New", Font.BOLD, 30))
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 5
    self._jPanelConstraints.gridwidth = 2
    self._jPanel.add(self._jLabelAPISpace3, self._jPanelConstraints)

    # Create panel for IP info
    self._jLabelIPListen = swing.JLabel("Listen on IP:")
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 6
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jLabelIPListen, self._jPanelConstraints)

    self._jTextFieldIPListen = swing.JTextField("127.0.0.1",15)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 1
    self._jPanelConstraints.gridy = 6
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jTextFieldIPListen, self._jPanelConstraints)

    # Create panel for Port info
    self._jLabelPortListen = swing.JLabel("Listen on Port:")
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 7
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jLabelPortListen, self._jPanelConstraints)

    self._jTextFieldPortListen = swing.JTextField("9090",3)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 1
    self._jPanelConstraints.gridy = 7
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jTextFieldPortListen, self._jPanelConstraints)

    # Create panel to contain Python button
    self._jLabelPython = swing.JLabel("Select Python:")
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 8
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jLabelPython, self._jPanelConstraints)

    self._jButtonSetPython = swing.JButton('Python', actionPerformed=self.setPython)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 1
    self._jPanelConstraints.gridy = 8
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jButtonSetPython, self._jPanelConstraints)

    # Create panel to contain API button
    self._jLabelAPI = swing.JLabel("Select API:")
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 9
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jLabelAPI, self._jPanelConstraints)

    self._jButtonSetAPI = swing.JButton('SQLMap API', actionPerformed=self.setAPI)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 1
    self._jPanelConstraints.gridy = 9
    self._jPanelConstraints.gridwidth = 1
    self._jPanel.add(self._jButtonSetAPI, self._jPanelConstraints)

    # Create panel to execute API
    self._jButtonStartAPI = swing.JButton('Start API', actionPerformed=self.startAPI)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 10
    self._jPanelConstraints.gridwidth = 2
    self._jPanel.add(self._jButtonStartAPI, self._jPanelConstraints)

    # Create panel to stop API
    self._jButtonStopAPI = swing.JButton('Stop API', actionPerformed=self.stopAPI)
    self._jPanelConstraints.fill = awt.GridBagConstraints.HORIZONTAL
    self._jPanelConstraints.gridx = 0
    self._jPanelConstraints.gridy = 11
    self._jPanelConstraints.gridwidth = 2
    self._jPanel.add(self._jButtonStopAPI, self._jPanelConstraints)

    # Create SQLMap scanner panel
    # Combobox Values
    httpMethodValues = ['Default', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    levelValues = [1,2,3,4,5]
    riskValues = [0,1,2,3]
    threadValues = [1,2,3,4,5,6,7,8,9,10]
    delayValues = [0,1,2,3,4,5]
    timeoutValues = [1,5,10,15,20,25,30,35,40,45,50,55,60]
    retryValues = [1,2,3,4,5,6,7,8,9,10]
    dbmsValues = ['Any', 'MySQL', 'Oracle', 'PostgreSQL', 'Microsoft SQL Server', 'Microsoft Access', 'SQLite', 'Firebird', 'Sybase', 'SAP MaxDB', 'DB2']
    authTypes = ['None', 'Basic', 'Digest', 'NTLM']
    osValues = ['Any', 'Linux', 'Windows']
    timeSecValues = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    torTypes = ['HTTP', 'SOCKS4', 'SOCKS5']

    # GUI components
    self._jLabelScanText = swing.JLabel()
    self._jLabelScanIPListen = swing.JLabel()
    self._jLabelScanPortListen = swing.JLabel()
    self._jTextFieldScanIPListen = swing.JTextField()
    self._jTextFieldScanPortListen = swing.JTextField()
    self._jSeparator1 = swing.JSeparator()
    self._jLabelHttpMethod = swing.JLabel()
    self._jLabelIgnoreCode = swing.JLabel()
    self._jComboHttpMethod = swing.JComboBox(httpMethodValues)
    self._jTextFieldIgnoreCode = swing.JTextField()
    self._jLabelURL = swing.JLabel()
    self._jTextFieldURL = swing.JTextField()
    self._jLabelData = swing.JLabel()
    self._jTextData = swing.JTextArea()
    self._jScrollPaneData = swing.JScrollPane(self._jTextData)
    self._jLabelCookie = swing.JLabel()
    self._jTextFieldCookie = swing.JTextField()
    self._jLabelReferer = swing.JLabel()
    self._jTextFieldReferer = swing.JTextField()
    self._jLabelUA = swing.JLabel()
    self._jTextFieldUA = swing.JTextField()
    self._jLabelCustHeader = swing.JLabel()
    self._jTextFieldCustHeader = swing.JTextField()
    self._jSeparator2 = swing.JSeparator()
    self._jLabelParam = swing.JLabel()
    self._jTextFieldParam = swing.JTextField()
    self._jCheckTO = swing.JCheckBox()
    self._jSeparator3 = swing.JSeparator()
    self._jComboLevel = swing.JComboBox(levelValues)
    self._jLabelLevel = swing.JLabel()
    self._jLabelRisk = swing.JLabel()
    self._jComboRisk = swing.JComboBox(riskValues)
    self._jSeparator4 = swing.JSeparator()
    self._jCheckHPP = swing.JCheckBox('Param Pollution')
    self._jCheckCU = swing.JCheckBox('Current User')
    self._jCheckDB = swing.JCheckBox('Current DB')
    self._jCheckHost = swing.JCheckBox('Hostname')
    self._jCheckDBA = swing.JCheckBox('Is DBA?')
    self._jCheckUsers = swing.JCheckBox('List Users')
    self._jCheckPrivs = swing.JCheckBox('List Privs')
    self._jCheckPswds = swing.JCheckBox('List Passwords')
    self._jCheckRoles = swing.JCheckBox('List Roles')
    self._jCheckDBs = swing.JCheckBox('List DBs')
    self._jSeparator5 = swing.JSeparator()
    self._jLabelThreads = swing.JLabel()
    self._jLabelDelay = swing.JLabel()
    self._jLabelTimeout = swing.JLabel()
    self._jLabelRetry = swing.JLabel()
    self._jLabelTimeSec = swing.JLabel()
    self._jComboThreads = swing.JComboBox(threadValues)
    self._jComboDelay = swing.JComboBox(delayValues)
    self._jComboTimeout = swing.JComboBox(timeoutValues)
    self._jComboRetry = swing.JComboBox(retryValues)
    self._jComboTimeSec = swing.JComboBox(timeSecValues)
    self._jSeparator6 = swing.JSeparator()
    self._jLabelDBMS = swing.JLabel()
    self._jComboDBMS = swing.JComboBox(dbmsValues)
    self._jLabelOS = swing.JLabel()
    self._jComboOS = swing.JComboBox(osValues)
    self._jSeparator7 = swing.JSeparator()
    self._jLabelProxy = swing.JLabel()
    self._jTextFieldProxy = swing.JTextField()
    self._jSeparator8 = swing.JSeparator()
    self._jLabelTamper = swing.JLabel()
    self._jTextFieldTamper = swing.JTextField()
    self._jButtonStartScan = swing.JButton('Start Scan', actionPerformed=self.startScan)
    self._jLabelScanAPI = swing.JLabel()
    self._jLabelScanAPI.setText('SQLMap API is NOT running!')
    self._jLabelScanAPI.setForeground(Color.RED)
    self._jSeparator9 = swing.JSeparator()
    self._jSeparator10 = swing.JSeparator()
    self._jCheckTor = swing.JCheckBox('Enable Tor')
    self._jLabelTorType = swing.JLabel()
    self._jComboTorType = swing.JComboBox(torTypes)
    self._jLabelTorPort = swing.JLabel()
    self._jTextFieldTorPort = swing.JTextField()
    self._jSeparator11 = swing.JSeparator()
    self._jLabelAuthType = swing.JLabel()
    self._jComboAuthType = swing.JComboBox(authTypes)
    self._jLabelAuthUser = swing.JLabel()
    self._jTextFieldAuthUser = swing.JTextField()
    self._jLabelAuthPass = swing.JLabel()
    self._jTextFieldAuthPass = swing.JTextField()

    # Configure GUI
    self._jLabelScanText.setText('API Listening On:')
    self._jLabelScanIPListen.setText('SQLMap API IP:')
    self._jLabelScanPortListen.setText('SQLMap API Port:')
    self._jLabelHttpMethod.setText('HTTP Method:')
    self._jLabelIgnoreCode.setText('Ignore Error Code:')
    self._jComboHttpMethod.setSelectedIndex(0)
    self._jLabelURL.setText('URL:')
    self._jLabelData.setText('Post Data:')
    self._jTextData.setLineWrap(True)
    self._jScrollPaneData.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
    self._jLabelCookie.setText('Cookies:')
    self._jLabelReferer.setText('Referer:')
    self._jLabelUA.setText('User-Agent:')
    self._jLabelCustHeader.setText('Custom Headers:')
    self._jLabelParam.setText('Test Parameter(s):')
    self._jCheckTO.setText('Text Only')
    self._jLabelLevel.setText('Level:')
    self._jLabelRisk.setText('Risk:')
    self._jComboLevel.setSelectedIndex(2)
    self._jComboRisk.setSelectedIndex(1)
    self._jComboThreads.setSelectedIndex(0)
    self._jComboDelay.setSelectedIndex(0)
    self._jComboTimeout.setSelectedIndex(6)
    self._jComboRetry.setSelectedIndex(2)
    self._jComboTimeSec.setSelectedIndex(4)
    self._jComboDBMS.setSelectedIndex(0)
    self._jComboOS.setSelectedIndex(0)
    self._jComboTorType.setSelectedIndex(2)
    self._jLabelThreads.setText('Threads:')
    self._jLabelDelay.setText('Delay:')
    self._jLabelTimeout.setText('Timeout:')
    self._jLabelRetry.setText('Retries:')
    self._jLabelTimeSec.setText('Time-Sec:')
    self._jLabelDBMS.setText('DBMS Backend:')
    self._jLabelOS.setText('Operating System:')
    self._jLabelProxy.setText('Proxy (HTTP://IP:Port):')
    self._jLabelTamper.setText('Tamper Scripts:')
    self._jLabelTorType.setText('Tor Type:')
    self._jLabelTorPort.setText('Tor Port:')
    self._jTextFieldTorPort.setText('9050')
    self._jLabelAuthType.setText('Auth Type:')
    self._jLabelAuthUser.setText('Auth User:')
    self._jLabelAuthPass.setText('Auth Pass:')
    self._jComboAuthType.setSelectedIndex(0)

    # Configure locations
    self._jLabelScanText.setBounds(15, 16, 126, 20)
    self._jLabelScanIPListen.setBounds(15, 58, 115, 20)
    self._jLabelScanPortListen.setBounds(402, 55, 129, 20)
    self._jTextFieldScanIPListen.setBounds(167, 52, 206, 26)
    self._jTextFieldScanPortListen.setBounds(546, 52, 63, 26)
    self._jSeparator1.setBounds(15, 96, 790, 10)
    self._jLabelHttpMethod.setBounds(15, 117, 100, 26)
    self._jLabelIgnoreCode.setBounds(402, 117, 129, 26)
    self._jComboHttpMethod.setBounds(166, 117, 150, 26)
    self._jTextFieldIgnoreCode.setBounds(546, 117, 63, 26)
    self._jLabelURL.setBounds(15, 193, 35, 20)
    self._jTextFieldURL.setBounds(166, 190, 535, 26)
    self._jLabelData.setBounds(15, 232, 73, 20)
    self._jScrollPaneData.setBounds(166, 232, 535, 96)
    self._jLabelCookie.setBounds(15, 347, 61, 20)
    self._jTextFieldCookie.setBounds(166, 347, 535, 26)
    self._jLabelReferer.setBounds(15, 396, 57, 20)
    self._jTextFieldReferer.setBounds(166, 396, 535, 26)
    self._jLabelUA.setBounds(15, 445, 86, 20)
    self._jTextFieldUA.setBounds(166, 445, 535, 26)
    self._jLabelCustHeader.setBounds(15, 494, 132, 20)
    self._jTextFieldCustHeader.setBounds(166, 494, 535, 26)
    self._jSeparator2.setBounds(15, 535, 790, 10)
    self._jLabelParam.setBounds(15, 559, 132, 20)
    self._jTextFieldParam.setBounds(165, 556, 366, 26)
    self._jCheckTO.setBounds(584, 555, 101, 29)
    self._jSeparator3.setBounds(15, 602, 790, 10)
    self._jComboLevel.setBounds(165, 620, 180, 26)
    self._jLabelLevel.setBounds(15, 623, 42, 20)
    self._jLabelRisk.setBounds(430, 623, 35, 20)
    self._jComboRisk.setBounds(518, 620, 180, 26)
    self._jSeparator4.setBounds(15, 664, 790, 10)
    self._jCheckHPP.setBounds(15, 684, 145, 29)
    self._jCheckCU.setBounds(191, 684, 123, 29)
    self._jCheckDB.setBounds(340, 684, 111, 29)
    self._jCheckHost.setBounds(469, 684, 103, 29)
    self._jCheckDBA.setBounds(599, 684, 105, 29)
    self._jCheckUsers.setBounds(15, 731, 101, 29)
    self._jCheckPswds.setBounds(191, 731, 135, 29)
    self._jCheckPrivs.setBounds(344, 731, 95, 29)
    self._jCheckRoles.setBounds(469, 731, 99, 29)
    self._jCheckDBs.setBounds(599, 731, 89, 29)
    self._jSeparator5.setBounds(15, 772, 790, 10)
    self._jLabelThreads.setBounds(15, 795, 63, 20)
    self._jLabelDelay.setBounds(173, 795, 45, 20)
    self._jLabelTimeout.setBounds(326, 795, 65, 20)
    self._jLabelRetry.setBounds(484, 795, 48, 20)
    self._jLabelTimeSec.setBounds(642, 795, 65, 20)
    self._jComboThreads.setBounds(80, 792, 78, 26)
    self._jComboDelay.setBounds(233, 792, 78, 26)
    self._jComboTimeout.setBounds(391, 792, 78, 26)
    self._jComboRetry.setBounds(549, 792, 78, 26)
    self._jComboTimeSec.setBounds(717, 792, 78, 26)
    self._jSeparator6.setBounds(15, 834, 790, 10)
    self._jLabelDBMS.setBounds(15, 857, 110, 20)
    self._jComboDBMS.setBounds(143, 854, 191, 26)
    self._jLabelOS.setBounds(352, 857, 132, 20)
    self._jComboOS.setBounds(502, 854, 191, 26)
    self._jSeparator7.setBounds(15, 896, 790, 10)
    self._jLabelProxy.setBounds(15, 920, 171, 20)
    self._jTextFieldProxy.setBounds(204, 917, 256, 26)
    self._jSeparator8.setBounds(15, 963, 790, 10)
    self._jCheckTor.setBounds(15, 987, 171, 20)
    self._jLabelTorType.setBounds(206, 984, 65, 26)
    self._jComboTorType.setBounds(291, 984, 100, 26)
    self._jLabelTorPort.setBounds(460, 984, 129, 26)
    self._jTextFieldTorPort.setBounds(545, 984, 65, 26)
    self._jSeparator9.setBounds(15, 1030, 790, 10)
    self._jLabelTamper.setBounds(15, 1055, 171, 20)
    self._jTextFieldTamper.setBounds(204, 1052, 256, 26)
    self._jSeparator10.setBounds(15, 1098, 790, 10)
    self._jLabelAuthType.setBounds(15, 1123, 171, 20)
    self._jComboAuthType.setBounds(204, 1123, 100, 26)
    self._jLabelAuthUser.setBounds(15, 1172, 171, 20)
    self._jTextFieldAuthUser.setBounds(204, 1172, 256, 26)
    self._jLabelAuthPass.setBounds(15, 1221, 171, 20)
    self._jTextFieldAuthPass.setBounds(204, 1221, 256, 26)
    self._jSeparator11.setBounds(15, 1267, 790, 10)
    self._jButtonStartScan.setBounds(346, 1292, 103, 29)
    self._jLabelScanAPI.setBounds(167, 16, 275, 20)

    # Create main panel
    self._jScanPanel = swing.JPanel()
    self._jScanPanel.setLayout(None)
    self._jScanPanel.setPreferredSize(awt.Dimension(1368,1368))
    self._jScanPanel.add(self._jLabelScanText)
    self._jScanPanel.add(self._jLabelScanIPListen)
    self._jScanPanel.add(self._jLabelScanPortListen)
    self._jScanPanel.add(self._jTextFieldScanIPListen)
    self._jScanPanel.add(self._jTextFieldScanPortListen)
    self._jScanPanel.add(self._jSeparator1)
    self._jScanPanel.add(self._jLabelURL)
    self._jScanPanel.add(self._jTextFieldURL)
    self._jScanPanel.add(self._jLabelData)
    self._jScanPanel.add(self._jScrollPaneData)
    self._jScanPanel.add(self._jLabelCookie)
    self._jScanPanel.add(self._jTextFieldCookie)
    self._jScanPanel.add(self._jLabelReferer)
    self._jScanPanel.add(self._jTextFieldReferer)
    self._jScanPanel.add(self._jLabelHttpMethod)
    self._jScanPanel.add(self._jLabelIgnoreCode)
    self._jScanPanel.add(self._jComboHttpMethod)
    self._jScanPanel.add(self._jTextFieldIgnoreCode)
    self._jScanPanel.add(self._jLabelUA)
    self._jScanPanel.add(self._jTextFieldUA)
    self._jScanPanel.add(self._jLabelCustHeader)
    self._jScanPanel.add(self._jTextFieldCustHeader)
    self._jScanPanel.add(self._jSeparator2)
    self._jScanPanel.add(self._jLabelParam)
    self._jScanPanel.add(self._jTextFieldParam)
    self._jScanPanel.add(self._jCheckTO)
    self._jScanPanel.add(self._jSeparator3)
    self._jScanPanel.add(self._jComboLevel)
    self._jScanPanel.add(self._jLabelLevel)
    self._jScanPanel.add(self._jLabelRisk)
    self._jScanPanel.add(self._jComboRisk)
    self._jScanPanel.add(self._jSeparator4)
    self._jScanPanel.add(self._jCheckHPP)
    self._jScanPanel.add(self._jCheckCU)
    self._jScanPanel.add(self._jCheckDB)
    self._jScanPanel.add(self._jCheckHost)
    self._jScanPanel.add(self._jCheckDBA)
    self._jScanPanel.add(self._jCheckUsers)
    self._jScanPanel.add(self._jCheckPswds)
    self._jScanPanel.add(self._jCheckPrivs)
    self._jScanPanel.add(self._jCheckRoles)
    self._jScanPanel.add(self._jCheckDBs)
    self._jScanPanel.add(self._jSeparator5)
    self._jScanPanel.add(self._jLabelThreads)
    self._jScanPanel.add(self._jLabelDelay)
    self._jScanPanel.add(self._jLabelTimeout)
    self._jScanPanel.add(self._jLabelRetry)
    self._jScanPanel.add(self._jLabelTimeSec)
    self._jScanPanel.add(self._jComboThreads)
    self._jScanPanel.add(self._jComboDelay)
    self._jScanPanel.add(self._jComboTimeout)
    self._jScanPanel.add(self._jComboRetry)
    self._jScanPanel.add(self._jComboTimeSec)
    self._jScanPanel.add(self._jSeparator6)
    self._jScanPanel.add(self._jLabelDBMS)
    self._jScanPanel.add(self._jComboDBMS)
    self._jScanPanel.add(self._jLabelOS)
    self._jScanPanel.add(self._jComboOS)
    self._jScanPanel.add(self._jSeparator7)
    self._jScanPanel.add(self._jLabelProxy)
    self._jScanPanel.add(self._jTextFieldProxy)
    self._jScanPanel.add(self._jSeparator8)
    self._jScanPanel.add(self._jCheckTor)
    self._jScanPanel.add(self._jLabelTorType)
    self._jScanPanel.add(self._jComboTorType)
    self._jScanPanel.add(self._jLabelTorPort)
    self._jScanPanel.add(self._jTextFieldTorPort)
    self._jScanPanel.add(self._jSeparator9)
    self._jScanPanel.add(self._jLabelTamper)
    self._jScanPanel.add(self._jTextFieldTamper)
    self._jScanPanel.add(self._jSeparator10)
    self._jScanPanel.add(self._jLabelAuthType)
    self._jScanPanel.add(self._jComboAuthType)
    self._jScanPanel.add(self._jLabelAuthUser)
    self._jScanPanel.add(self._jTextFieldAuthUser)
    self._jScanPanel.add(self._jLabelAuthPass)
    self._jScanPanel.add(self._jTextFieldAuthPass)
    self._jScanPanel.add(self._jSeparator11)
    self._jScanPanel.add(self._jButtonStartScan)
    self._jScanPanel.add(self._jLabelScanAPI)
    self._jScrollPaneMain = swing.JScrollPane(self._jScanPanel)
    self._jScrollPaneMain.setViewportView(self._jScanPanel)
    self._jScrollPaneMain.setPreferredSize(awt.Dimension(1357,1357))

    # Create SQLMap log JPanel
    self._jLogPanel = swing.JPanel()
    self._jLogPanel.setLayout(None)

    # Create label, combobox, and button to get logs and textarea to display them
    self._jLabelLog = swing.JLabel("Logs for Scan ID:")
    self._jComboLogs = swing.JComboBox(self.scantasks)
    self._jButtonGetLogs = swing.JButton('Get', actionPerformed=self.getLogs)
    self._jButtonRemoveLogs = swing.JButton('Remove', actionPerformed=self.removeLogs)
    self._jTextLogs = swing.JTextArea()
    self._jTextLogs.setColumns(50)
    self._jTextLogs.setRows(50)
    self._jTextLogs.setLineWrap(True)
    self._jTextLogs.setEditable(False)
    self._jScrollPaneLogs = swing.JScrollPane(self._jTextLogs)
    self._jScrollPaneLogs.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

    self._jLabelLog.setBounds(15, 16, 126, 20)
    self._jComboLogs.setBounds(167, 16, 535, 20)
    self._jButtonGetLogs.setBounds(718, 16, 50, 20)
    self._jButtonRemoveLogs.setBounds(783, 16, 80, 20)
    self._jScrollPaneLogs.setBounds(15, 58, 846, 400)

    self._jLogPanel.add(self._jLabelLog)
    self._jLogPanel.add(self._jComboLogs)
    self._jLogPanel.add(self._jButtonGetLogs)
    self._jLogPanel.add(self._jButtonRemoveLogs)
    self._jLogPanel.add(self._jScrollPaneLogs)

    # Create SQLMap stop scan JPanel
    self._jStopScanPanel = swing.JPanel()
    self._jStopScanPanel.setLayout(None)

    # Create label, combobox, and button to stop scans and textfield to display success
    self._jLabelStopScan = swing.JLabel("Stop Scan ID:")
    self._jComboStopScan = swing.JComboBox(self.scantasks)
    self._jButtonStopScan = swing.JButton('Stop', actionPerformed=self.stopScan)
    self._jButtonRemoveScan = swing.JButton('Remove', actionPerformed=self.removeScan)
    self._jLabelStopStatus = swing.JLabel()

    self._jLabelStopScan.setBounds(15, 16, 126, 20)
    self._jComboStopScan.setBounds(167, 16, 535, 20)
    self._jButtonStopScan.setBounds(718, 16, 55, 20)
    self._jButtonRemoveScan.setBounds(783, 16, 80, 20)
    self._jLabelStopStatus.setBounds(167, 58, 846, 20)

    self._jStopScanPanel.add(self._jLabelStopScan)
    self._jStopScanPanel.add(self._jComboStopScan)
    self._jStopScanPanel.add(self._jButtonStopScan)
    self._jStopScanPanel.add(self._jButtonRemoveScan)
    self._jStopScanPanel.add(self._jLabelStopStatus)

    # Setup Tabs
    self._jConfigTab = swing.JTabbedPane()
    self._jConfigTab.addTab("SQLMap API", self._jPanel)
    self._jConfigTab.addTab("SQLMap Scanner", self._jScrollPaneMain)
    self._jConfigTab.addTab("SQLMap Logs", self._jLogPanel)
    self._jConfigTab.addTab("SQLMap Scan Stop", self._jStopScanPanel)

    # Automatically get and set the Python path if we can find it
    pythonpath = ''
    pythonregpath1 = ''
    pythonregpath2 = ''
    pathpart1 = ''
    pathpart2 = ''
    drivepart1 = ''
    drivepart2 = ''
    pythonaltpath1 = ''
    pythonaltpath2 = ''
    path_delim = ''
    ostype = System.getProperty('os.name')

    try:
      if 'Windows' in ostype:
        path_delim = '\\'

        try:
          pythonpath = subprocess.check_output(['where', 'python']).split('\n')[0].rstrip('\n\r')
        except:
          print 'Could not find python.exe in path.\n'

        try:
          pythonregpath1 = subprocess.check_output('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\2.7\\InstallPath" /ve')
          pathpart1 = pythonregpath1.rsplit(':', 1)[1].rstrip('\n\r')
          drivepart1 = pythonregpath1.rsplit(':', 1)[0][-1]
        except:
          print 'Could not find python path in registry at: HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\2.7\\InstallPath.\n'

        try:
          pythonregpath2 = subprocess.check_output('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Python\\PythonCore\\2.7\InstallPath" /ve')
          pathpart2 = pythonregpath2.rsplit(':', 1)[1].rstrip('\n\r')
          drivepart2 = pythonregpath2.rsplit(':', 1)[0][-1]
        except:
          print 'Could not find python path in registry at: HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Python\\PythonCore\\2.7\InstallPath.\n'

        if re.search('[pP]ython', pathpart1):
          pythonaltpath1 = drivepart1 + ':' + pathpart1 + path_delim + 'python.exe'

        if re.search('[pP]ython', pathpart2):
          pythonaltpath2 = drivepart2 + ':' + pathpart2 + path_delim + 'python.exe'
      else:
        path_delim = '/'

        try:
          pythonpath = subprocess.check_output(['which', 'python2.7']).split('\n')[0].rstrip('\n\r')
        except:
          print 'Could not find python.exe in path.\n'
    except:
      print 'Could not get OS version, therefore could not find Python path\n'

    # Set python variables
    if re.search('python.exe', pythonpath) or re.search('\/python2.7$', pythonpath):
      self.pythonfile = pythonpath
      print 'Python found in system path at: ' + pythonpath + '\n'
    elif re.search('python.exe', pythonaltpath1):
      self.pythonfile = pythonaltpath1
      print 'Python found in registry under HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\2.7\\InstallPath at: ' + pythonaltpath1 + '\n'
    elif re.search('python.exe', pythonaltpath2):
      self.pythonfile = pythonaltpath2
      print 'Python found in registry under HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Python\\PythonCore\\2.7\InstallPath at: ' + pythonaltpath2 + '\n'
    else:
      print 'Could not set the correct Python path.\n'

    # Get Python version to confirm 2.7.x
    if 'Windows' in ostype and re.search('python.exe', self.pythonfile):
      try:
        pythonver = subprocess.check_output(self.pythonfile + ' -c "import sys; print str(sys.version_info[0]) + str(sys.version_info[1])"').rstrip('\n\r')
        if pythonver == '27':
          self._jLabelPython.setText('Python set to: ' + self.pythonfile)
        else:
          self.pythonfile = ''
          print 'Wrong version of Python: ' + pythonver[0] + '.' + pythonver[1] + '\n'
      except:
        print 'Could not get Python version\n'
    elif re.search('python2.7', self.pythonfile):
      self._jLabelPython.setText('Python set to: ' + self.pythonfile)
    else:
      print 'Wrong version of Python or something went wrong.\n'

    # Automatically set the sqlmapapi, first unzip if the extension has never run
    if os.path.isfile(os.getcwd() + path_delim + 'sqlmap.zip'):

      # Extract sqlmap
      try:
        with zipfile.ZipFile(os.getcwd() + path_delim + 'sqlmap.zip') as sqlmapzip:
          sqlmapzip.extractall(os.getcwd() + path_delim)

        # Remove sqlmap zip file
        os.remove(os.getcwd() + path_delim + 'sqlmap.zip')

        # Set API
        if os.path.isfile(os.getcwd() + path_delim + 'sqlmap' + path_delim + 'sqlmapapi.py'):
          self._jLabelAPI.setText('API set to: ' + os.getcwd() + path_delim + 'sqlmap' + path_delim + 'sqlmapapi.py')
          self.apifile = os.getcwd() + path_delim + 'sqlmap' + path_delim + 'sqlmapapi.py'
          print 'SQLMap API found at: ' + self.apifile + '\n'
        else:
          print 'Could not find SQLMap API file.\n'
      except:
        print 'Failed to extract sqlmap.zip\n'
    else:
      # Set API
      if os.path.isfile(os.getcwd() + path_delim + 'sqlmap' + path_delim + 'sqlmapapi.py'):
        self._jLabelAPI.setText('API set to: ' + os.getcwd() + path_delim + 'sqlmap' + path_delim + 'sqlmapapi.py')
        self.apifile = os.getcwd() + path_delim + 'sqlmap' + path_delim + 'sqlmapapi.py'
        print 'SQLMap API found at: ' + self.apifile + '\n'
      else:
        print 'Could not find SQLMap API file.\n'

    callbacks.customizeUiComponent(self._jConfigTab)
    callbacks.addSuiteTab(self)
    return

    # Create a menu item if the appropriate section of the UI is selected
  def createMenuItems(self, invocation):
    menu = []

    # Which part of the interface the user selects
    ctx = invocation.getInvocationContext()

    # Message Viewer Req will show menu item if selected by the user
    if ctx == 0 or ctx == 2:
      menu.append(swing.JMenuItem("SQLiPy Scan", None, actionPerformed=lambda x, inv=invocation: self.sqlMapScan(inv)))

    return menu if menu else None

  def getTabCaption(self):
    return 'SQLiPy'

  def getUiComponent(self):
    return self._jConfigTab

  def sqlMapScan(self, invocation):

    # Check initial message for proper request/response and set variables - Burp will not return valid info otherwise
      try:
        invMessage = invocation.getSelectedMessages()
        message = invMessage[0]
        reqInfo = self._helpers.analyzeRequest(message)
        reqUrl = str(reqInfo.getUrl())
        reqBody = message.getRequest()
        bodyData = self._helpers.bytesToString(reqBody[reqInfo.getBodyOffset():])
        reqHeaders = newHeaders = list(reqInfo.getHeaders())
        referer = ''
        ua = ''
        cookie = ''

        for header in reqHeaders:
          if re.search('^Referer', header, re.IGNORECASE) is not None:
            referer = re.sub('^Referer\:\s+', '', header, re.IGNORECASE)
          elif re.search('^User-Agent', header, re.IGNORECASE) is not None:
            ua = re.sub('^User-Agent\:\s+', '', header, re.IGNORECASE)
          elif re.search('^Cookie', header, re.IGNORECASE) is not None:
            cookie = re.sub('^Cookie\:\s+', '', header, re.IGNORECASE)

        self._jTextFieldURL.setText(reqUrl)
        self._jTextData.setText(bodyData)
        self._jTextFieldCookie.setText(cookie)
        self._jTextFieldUA.setText(ua)
        self._jTextFieldReferer.setText(referer)
        self._jConfigTab.setSelectedComponent(self._jScrollPaneMain)
        self.scanMessage = message
        self.scanUrl = reqInfo.getUrl()
        parentTab = self._jConfigTab.getParent()
        parentTab.setSelectedComponent(self._jConfigTab)
      except:
        print 'Failed to add data to scan tab.'

  def printHeader(self):
    print 'SQLiPy - 0.8.0\nBurp interface to SQLMap via the SQLMap API\njosh.berry@codewatch.org\n\n'

  def setAPI(self, e):
    selectFile = swing.JFileChooser()
    filter = swing.filechooser.FileNameExtensionFilter("python files", ["py"])
    selectFile.addChoosableFileFilter(filter)

    returnedFile = selectFile.showDialog(self._jPanel, "SQLMap API")

    if returnedFile == swing.JFileChooser.APPROVE_OPTION:
      file = selectFile.getSelectedFile()
      self.apifile = file.getPath()
      print 'Selected API at ' + file.getPath()
      self._jLabelAPI.setText('API set to: ' + file.getPath())

  def setPython(self, e):
    selectFile = swing.JFileChooser()

    returnedFile = selectFile.showDialog(self._jPanel, "Python EXE")

    if returnedFile == swing.JFileChooser.APPROVE_OPTION:
      file = selectFile.getSelectedFile()
      self.pythonfile = file.getPath()
      print 'Selected Python at ' + file.getPath()
      self._jLabelPython.setText('Python set to: ' + file.getPath())

  def startAPI(self, button):
    if self.apistatus == 0:
      try:
        print 'Calling: ' + self.pythonfile + ' ' + self.apifile + ' -s -H ' + self._jTextFieldIPListen.getText() + ' -p ' + self._jTextFieldPortListen.getText() + '\n'
        sqlmapdir = ''

        if re.search('^[a-zA-Z]\:', self.apifile) is not None:
          sqlmapdir = self.apifile.rsplit('\\', 1)[0]
        else:
          sqlmapdir = self.apifile.rsplit('/', 1)[0]

        javaexec = getattr(Runtime.getRuntime(), "exec")
        cmd = [self.pythonfile, self.apifile, "-s", "-H", self._jTextFieldIPListen.getText(), "-p", self._jTextFieldPortListen.getText()]

        self.apiprocess = javaexec(cmd, None, File(sqlmapdir))

        self.errorGobbler = Thread(StreamGobbler(self.apiprocess.getErrorStream(), System.err))
        self.outputGobbler = Thread(StreamGobbler(self.apiprocess.getInputStream(), System.out))

        self.errorGobbler.start()
        self.outputGobbler.start()

        # Final validation the API is running
        try:
          time.sleep(5)
          req = urllib2.Request('http://' + self._jTextFieldIPListen.getText() + ':' + self._jTextFieldPortListen.getText() + '/scan/0/status')
          req.add_header('Content-Type', 'application/json')
          resp = json.load(urllib2.urlopen(req, timeout=10))

          if resp['message'] == "Invalid task ID":
            self._jLabelScanAPI.setText(self._jTextFieldIPListen.getText() + ':' + self._jTextFieldPortListen.getText())
            self._jLabelScanAPI.setForeground(Color.GREEN)
            self._jTextFieldScanIPListen.setText(self._jTextFieldIPListen.getText())
            self._jTextFieldScanPortListen.setText(self._jTextFieldPortListen.getText())
            self._jLabelAPIStatus.setText('SQLMap API IS CURRENTLY RUNNING!')
            self._jLabelAPIStatus.setForeground(Color.GREEN)
            self.apistatus = 1

            print 'SQLMap API started.\n'
        except:
          self.apiprocess.destroy()
          self.errorGobbler.join()
          self.outputGobbler.join()
          print 'Failed to start the SQLMap API\n'

      except:
        print 'Failed to start the SQLMap API\n'
    else:
      print 'The SQLMap API process has already been started\n'

  def stopAPI(self, button):
    if self.apistatus == 1:
      try:
        if self._jComboStopScan.getItemCount() is not 0:
          for item in range(0, self._jComboStopScan.getItemCount()):
            req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/scan/' + self._jComboStopScan.getItemAt(item).split('-')[0] + '/kill')
            resp = json.load(urllib2.urlopen(req, timeout=3))

            if resp['success'] == True:
              print 'Scan stopped for ID: '+ self._jComboStopScan.getItemAt(item).split('-')[0]+'\n'
            else:
              print 'Failed to stop scan on ID: '+self._jComboStopScan.getItemAt(item).split('-')[0]+', likely already completed\n'
        
      except:
        print 'Failed to stop currently running SQLMap scans or no scans were still running\n'

      try:
        totalThreads = 1

        for thread in self.threads:
          print 'Stopping running scan check thread: ' + str(totalThreads) + '\n'
          totalThreads += 1
          thread.keep_running = False
          thread.join()

        i = 0
        while i < len(self.threads):
          self.threads.pop(0)
          i += 1

      except:
        print 'Could not stop running threads\n'

      try:
        self.apiprocess.destroy()
        self._jComboLogs.removeAllItems()
        self._jComboStopScan.removeAllItems()
        self._jLabelScanAPI.setText('SQLMap API is NOT running!')
        self._jLabelScanAPI.setForeground(Color.RED)
        self._jLabelAPIStatus.setText('SQLMap API is NOT running!')
        self._jLabelAPIStatus.setForeground(Color.RED)
        self.apistatus = 0

        print 'Stopping the SQLMap API\n'
      except:
        print 'Failed to stop the SQLMap API\n'

      try:
          self.errorGobbler.join()
          self.outputGobbler.join()

          print 'Stopping API input/output/error buffers threads\n'
      except:
          print 'Failed to stop API input/output/error buffers threads\n'

  def extensionUnloaded(self):
    if self.apistatus == 1:
      try:
        if self._jComboStopScan.getItemCount() is not 0:
          for item in range(0, self._jComboStopScan.getItemCount()):
            req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/scan/' + self._jComboStopScan.getItemAt(item).split('-')[0] + '/kill')
            resp = json.load(urllib2.urlopen(req, timeout=3))

            if resp['success'] == True:
              print 'Scan stopped for ID: '+ self._jComboStopScan.getItemAt(item).split('-')[0]+'\n'
            else:
              print 'Failed to stop scan on ID: '+self._jComboStopScan.getItemAt(item).split('-')[0]+', likely already completed\n'
        
      except:
        print 'Failed to stop currently running SQLMap scans or no scans were still running\n'

      try:
        totalThreads = 1

        for thread in self.threads:
          print 'Stopping running scan check thread: ' + str(totalThreads) + '\n'
          totalThreads += 1
          thread.keep_running = False
          thread.join()

      except:
        print 'Could not stop running threads\n'

      try:
        self.apiprocess.destroy()
        print 'Stopping the SQLMap API...\n'
      except:
        print 'Failed to stop the SQLMap API\n'

      try:
          self.errorGobbler.join()
          self.outputGobbler.join()

          print 'Stopping API input/output/error buffers threads\n'
      except:
          print 'Failed to stop API input/output/error buffers threads\n'

  def getLogs(self, button):
    try:
      req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/scan/' + self._jComboLogs.getSelectedItem().split('-')[0] + '/log')
      resp = json.load(urllib2.urlopen(req, timeout=10))

      if resp['success'] == True:
        logdata = ''
        for logs in resp['log']:
          logdata = logdata + logs['level'] + ': ' + logs['time'] + ' - ' + logs['message'] + '\n'

        self._jTextLogs.setText('Log results for: ' + self.scancmds[self._jComboLogs.getSelectedItem().split('-')[0]] + logdata)
      else:
        print 'Failed to get logs for: '+self._jComboLogs.getSelectedItem().split('-')[0]+'\n'
    except:
      print 'Failed to get logs for: '+self._jComboLogs.getSelectedItem().split('-')[0]+'\n'

  def removeLogs(self, button):
    print 'Removing Log Entry for ID: '+ self._jComboLogs.getSelectedItem().split('-')[0]+'\n'
    self._jComboLogs.removeItem(self._jComboLogs.getSelectedItem())

  def stopScan(self, button):
    try:
      req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/scan/' + self._jComboStopScan.getSelectedItem().split('-')[0] + '/kill')
      resp = json.load(urllib2.urlopen(req, timeout=10))

      if resp['success'] == True:
        print 'Scan stopped for ID: '+ self._jComboStopScan.getSelectedItem().split('-')[0]+'\n'
        self._jLabelStopStatus.setText('Scan stopped for ID: ' + self._jComboStopScan.getSelectedItem().split('-')[0])
        self._jComboStopScan.removeItem(self._jComboStopScan.getSelectedItem())
      else:
        print 'Failed to stop scan on ID: '+self._jComboStopScan.getSelectedItem().split('-')[0]+', likely already completed\n'
        self._jLabelStopStatus.setText('Failed to stop scan on ID: '+self._jComboStopScan.getSelectedItem().split('-')[0]+', likely already completed')
    except:
      print 'Failed to stop scan on ID: '+self._jComboStopScan.getSelectedItem().split('-')[0]+', likely already completed\n'
      self._jLabelStopStatus.setText('Failed to stop scan on ID: '+self._jComboStopScan.getSelectedItem().split('-')[0]+', likely already completed')

  def removeScan(self, button):
    print 'Removing Scan Stop Entry for ID: '+ self._jComboStopScan.getSelectedItem().split('-')[0]+'\n'
    self._jLabelStopStatus.setText('Scan removed from stop tab for ID: ' + self._jComboStopScan.getSelectedItem().split('-')[0])
    self._jComboStopScan.removeItem(self._jComboStopScan.getSelectedItem())

  def startScan(self, button):
    hpp = ''
    cu = ''
    cdb = ''
    hostname = ''
    isdba = ''
    lusers = ''
    lpswds = ''
    lprivs = ''
    lroles = ''
    ldbs = ''
    textonly = ''
    postdata = None
    datacmd = ''
    cookiedata = None
    cookiecmd = ''
    uadata = None
    uacmd = ''
    ignorecodedata = None
    ignorecodecmd = ''
    custheaderdata = None
    custheadercmd = ''
    headerdata = None
    headercmd = ''
    refererdata = None
    referercmd = ''
    proxy = None
    proxycmd = ''
    dbms = None
    dbmscmd = ''
    os = None
    oscmd = ''
    tampercmd = ''
    tamperdata = None
    paramcmd = ''
    paramdata = None
    csrfurl = None
    csrftoken = None
    torcmd = ''
    tortypecmd = ''
    torportcmd = ''
    httpmethod = None
    httpmethodcmd = ''
    authtype = None
    authtypecmd = ''
    authcred = None
    authcredcmd = ''

    if self._jCheckTO.isSelected():
      textonly = ' --text-only'
      textonlystatus = True
    else:
      textonlystatus = False

    if self._jCheckHPP.isSelected():
      hpp = ' --hpp'
      hppstatus = True
    else:
      hppstatus = False

    if self._jCheckCU.isSelected():
      cu = ' --current-user'
      custatus = True
    else:
      custatus = False

    if self._jCheckDB.isSelected():
      cdb = ' --current-db'
      cdbstatus = True
    else:
      cdbstatus = False

    if self._jCheckHost.isSelected():
      hostname = ' --hostname'
      hostnamestatus = True
    else:
      hostnamestatus = False

    if self._jCheckDBA.isSelected():
      isdba = ' --is-dba'
      isdbastatus = True
    else:
      isdbastatus = False

    if self._jCheckUsers.isSelected():
      lusers = ' --users'
      lusersstatus = True
    else:
      lusersstatus = False

    if self._jCheckPswds.isSelected():
      lpswds = ' --passwords'
      lpswdsstatus = True
    else:
      lpswdsstatus = False

    if self._jCheckPrivs.isSelected():
      lprivs = ' --privileges'
      lprivsstatus = True
    else:
      lprivsstatus = False

    if self._jCheckRoles.isSelected():
      lroles = ' --roles'
      lrolesstatus = True
    else:
      lrolesstatus = False

    if self._jCheckDBs.isSelected():
      ldbs = ' --dbs'
      ldbsstatus = True
    else:
      ldbsstatus = False

    if self._jCheckTor.isSelected():
      torstatus = True
      torcmd = ' --tor'
      tortype = self._jComboTorType.getSelectedItem()
      tortypecmd = ' --tor-type=' + self._jComboTorType.getSelectedItem()
      torport = self._jTextFieldTorPort.getText()
      torportcmd = ' --tor-port=' + self._jTextFieldTorPort.getText()
    else:
      torstatus = False
      tortype = 'HTTP'
      torport = None

    if not re.search('^None$', self._jComboAuthType.getSelectedItem()) is not None and re.search('[a-zA-Z0-9]', self._jTextFieldAuthUser.getText()) is not None:
      authtype = self._jComboAuthType.getSelectedItem()
      authtypecmd = ' --auth-type=' + self._jComboAuthType.getSelectedItem()
      authuser = self._jTextFieldAuthUser.getText()
      authpass = self._jTextFieldAuthPass.getText()
      authcred = authuser + ':' + authpass
      authcredcmd = ' --auth-cred="' + authuser + ':' + authpass + '"'
    else:
      authtype = None
      authtypecmd = ''
      authuser = ''
      authpass = ''
      authcred = None
      authcredcmd = ''  

    if re.search('[a-zA-Z0-9]', self._jTextFieldIgnoreCode.getText()) is not None:
      ignorecodedata = self._jTextFieldIgnoreCode.getText()
      ignorecodecmd = ' --ignore-code=' + self._jTextFieldIgnoreCode.getText()

    if re.search('(http|https)\://', self._jTextFieldProxy.getText()) is not None:
      proxy = self._jTextFieldProxy.getText()
      proxycmd = ' --proxy=' + self._jTextFieldProxy.getText()

    if not re.search('^Default$', self._jComboHttpMethod.getSelectedItem()) is not None:
      httpmethod = self._jComboHttpMethod.getSelectedItem()
      httpmethodcmd = ' --method="' + self._jComboHttpMethod.getSelectedItem()+'"'

    if not re.search('^Any$', self._jComboDBMS.getSelectedItem()) is not None:
      dbms = self._jComboDBMS.getSelectedItem()
      dbmscmd = ' --dbms="' + self._jComboDBMS.getSelectedItem()+'"'

    if not re.search('^Any$', self._jComboOS.getSelectedItem()) is not None:
      os = self._jComboOS.getSelectedItem()
      oscmd = ' --os=' + self._jComboOS.getSelectedItem()

    if re.search('[a-zA-Z0-9]', self._jTextFieldTamper.getText()) is not None:
      tampercmd = ' --tamper="' + self._jTextFieldTamper.getText() + '"'
      tamperdata = self._jTextFieldTamper.getText()

    if re.search('[a-zA-Z0-9]', self._jTextData.getText()) is not None:
      postdata = self._jTextData.getText()
      datacmd = ' --data="' + self._jTextData.getText() + '"'

    if re.search('[a-zA-Z0-9]', self._jTextFieldCookie.getText()) is not None:
      cookiedata = self._jTextFieldCookie.getText()
      cookiecmd = ' --cookie="' + self._jTextFieldCookie.getText() + '"'

    if re.search('[a-zA-Z0-9]', self._jTextFieldUA.getText()) is not None:
      uadata = self._jTextFieldUA.getText()
      uacmd = ' --user-agent="' + self._jTextFieldUA.getText() + '"'

    if re.search('[a-zA-Z0-9]', self._jTextFieldCustHeader.getText()) is not None:
      custheaderdata = self._jTextFieldCustHeader.getText()
      custheadercmd = ' --headers="' + self._jTextFieldCustHeader.getText() + '"'

    if re.search('[a-zA-Z0-9]', self._jTextFieldReferer.getText()) is not None:
      refererdata = self._jTextFieldReferer.getText()
      referercmd = ' --referer="' + self._jTextFieldReferer.getText() + '"'

    if re.search('[a-zA-Z0-9]', self._jTextFieldParam.getText()) is not None:
      paramdata = self._jTextFieldParam.getText()
      paramcmd = ' -p "' + self._jTextFieldParam.getText() + '"'

    try:
      sqlmapcmd = 'sqlmap.py -u "' + self._jTextFieldURL.getText() + '"' + datacmd + httpmethodcmd + cookiecmd + uacmd + referercmd + custheadercmd + authtypecmd + authcredcmd + ignorecodecmd + proxycmd + torcmd + tortypecmd + torportcmd + ' --delay=' + str(self._jComboDelay.getSelectedItem()) + ' --timeout=' + str(self._jComboTimeout.getSelectedItem()) + ' --retries=' + str(self._jComboDelay.getSelectedItem()) + paramcmd + dbmscmd + oscmd + tampercmd + ' --level=' + str(self._jComboLevel.getSelectedItem()) + ' --risk=' + str(self._jComboRisk.getSelectedItem()) + textonly + hpp + ' --threads=' + str(self._jComboThreads.getSelectedItem()) + ' --time-sec=' + str(self._jComboTimeSec.getSelectedItem()) + ' -b' + cu + cdb + hostname + isdba + lusers + lpswds + lprivs + lroles + ldbs + ' --batch --answers="crack=N,dict=N"\n\n'
      print 'SQLMap Command: ' + sqlmapcmd
      req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/task/new')
      resp = json.load(urllib2.urlopen(req, timeout=10))

      if resp['success'] == True and resp['taskid']:
        sqlitask = resp['taskid']
        sqliopts = {'authType': authtype, 'csrfUrl': csrfurl, 'csrfToken': csrftoken, 'getUsers': lusersstatus, 'getPasswordHashes': lpswdsstatus, 'delay': self._jComboDelay.getSelectedItem(), 'isDba': isdbastatus, 'risk': self._jComboRisk.getSelectedItem(), 'getCurrentUser': custatus, 'getRoles': lrolesstatus, 'getPrivileges': lprivsstatus, 'testParameter': paramdata, 'timeout': self._jComboTimeout.getSelectedItem(), 'ignoreCode': ignorecodedata, 'torPort': torport, 'level': self._jComboLevel.getSelectedItem(), 'getCurrentDb': cdbstatus, 'answers': 'crack=N,dict=N', 'method': httpmethod, 'cookie': cookiedata, 'proxy': proxy, 'os': os, 'threads': self._jComboThreads.getSelectedItem(), 'url': self._jTextFieldURL.getText(), 'getDbs': ldbsstatus, 'tor': torstatus, 'torType': tortype, 'referer': refererdata, 'retries': self._jComboRetry.getSelectedItem(), 'headers': custheaderdata, 'authCred': authcred, 'timeSec': self._jComboTimeSec.getSelectedItem(), 'getHostname': hostnamestatus, 'agent': uadata, 'dbms': dbms, 'tamper': tamperdata, 'hpp': hppstatus, 'getBanner': 'true', 'data': postdata, 'textOnly': textonlystatus}

        print 'Created SQLMap Task: ' + sqlitask + '\n'

        try:
          req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/option/' + sqlitask + '/set')
          req.add_header('Content-Type', 'application/json')
          resp = json.load(urllib2.urlopen(req, json.dumps(sqliopts), timeout=10))

          if resp['success'] == True:
            print 'SQLMap options set on Task ' + sqlitask + ': ' + json.dumps(sqliopts) + '\n'
            sqliopts = {'url': self._jTextFieldURL.getText()}

            try:
              checkreq = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/option/' + sqlitask + '/list')
              checkresp = json.load(urllib2.urlopen(checkreq, timeout=10))
              print 'SQLMap options returned: ' + json.dumps(checkresp) + '\n'
            except:
              print 'Failed to get list of options from SQLMap API\n'

            try:
              req = urllib2.Request('http://' + self._jTextFieldScanIPListen.getText() + ':' + self._jTextFieldScanPortListen.getText() + '/scan/' + sqlitask + '/start')
              req.add_header('Content-Type', 'application/json')
              resp = json.load(urllib2.urlopen(req, json.dumps(sqliopts), timeout=10))

              if resp['success'] == True:
                findings = ThreadExtender(self, self._jTextFieldScanIPListen.getText(), self._jTextFieldScanPortListen.getText(), sqlitask, self.scanUrl, self.scanMessage, self._callbacks)
                t = threading.Thread(target=findings.checkResults)
                self.threads.append(t)
                t.start()
                self._jComboLogs.addItem(sqlitask + '-' + self._jTextFieldURL.getText())
                self._jComboStopScan.addItem(sqlitask + '-' + self._jTextFieldURL.getText())
                self.scancmds[sqlitask] = sqlmapcmd
                print 'Started SQLMap Scan on Task ' + sqlitask +' with Engine ID: ' + str(resp['engineid']) + ' - ' + self._jTextFieldURL.getText() + '\n'
              else:
                print 'Failed to start SQLMap Scan for Task: ' + sqlitask + '\n'

            except:
              print 'Failed to start SQLMap Scan for Task: ' + sqlitask + '\n'

          else:
            print 'Failed to set options on SQLMap Task: ' + sqlitask + '\n'

        except:
          print 'Failed to set options on SQLMap Task: ' + sqlitask + '\n'

      else:
        print 'SQLMap task creation failed\n'

    except:
      print 'SQLMap task creation failed\n'