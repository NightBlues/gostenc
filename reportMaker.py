__author__ = 'NightBlues'
import os
class reportMaker:

    def __init__(self, file, ext="html"):
        self.repOutPutFolder = "reports/"
        self.repOutPut = file
        self.extension = ext
        self.repHandle = False
        self.count = 0

    def getOutPut(self):
        return self.repOutPutFolder+self.repOutPut+hex(self.count)+"."+self.extension

    def openHandle(self):
        """
            Opens report file for writing.
        """
        if not os.path.exists(self.repOutPutFolder): os.makedirs(self.repOutPutFolder)
        self.repHandle = open(self.getOutPut(), "w")
        self.add("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" /><title>Report for </title></head><body>")

    def add(self, str):
        """
            Adds string to report
        """
        if not self.repHandle:
            self.openHandle()
        self.repHandle.write(str)

    def addList(self, ls):
        """
            Adding list to report
        """
        str = "<ul>"
        for l in ls:
            str += "<li>"+l+"</li>"
        str += "</ul>"
        self.add(str)

    def addHeader1(self, str):
        """
            Adds string copvered with H1 tags to report
        """
        self.add("<h1>"+str+"</h1>")

    def addHeader2(self, str):
        """
            Adds string copvered with H2 tags to report
        """
        self.add("<h2>"+str+"</h2>")

    def addHeader3(self, str):
        """
            Adds string copvered with H3 tags to report
        """
        self.add("<h3>"+str+"</h3>")

    def addBold(self, str):
        """
            Adds string copvered with H3 tags to report
        """
        self.add("<b>"+str+"</b><br>")


    def addError(self, str):
        """
            Adds string colored red to report
        """
        self.add("<font color=red>"+str+"</font><br>")