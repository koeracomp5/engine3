# -*- coding: utf-8 -*-
import threading
import time
from PyQt4.QtCore import pyqtSlot, Qt
from PyQt4.QtGui import *
from PyQt4 import QtCore, QtGui
import maingui
import sys
import win32gui as wg
import win32process
import psutil
import memprc
from winappdbg import HexDump, HexInput

# global variables
openpname = None
scantype = 'Exact Value'
valuetype = '4bytes'
hack = None


class myListWidget(QListWidget):
    def itemclick(self, item):
        global maindlg
        global hack
        print(item.pid, item.pname)
        hack = memprc.Hack(item.pname)
        maindlg.pnamelabel.setText(item.text())
        self.parentWidget().close()


class popenDialog(QDialog, maingui.Ui_popenDialog):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.listwidget = myListWidget(self)
        def get_all_windows():
            def call(hwnd, param):
                param.append(hwnd)
            winds = []
            wg.EnumWindows(call, winds)
            return winds

        wids = get_all_windows()
        pidset = set()
        for i in wids:
            _, pid = win32process.GetWindowThreadProcessId(i)
            pidset.add(pid)

        for pi in pidset:
            item = QtGui.QListWidgetItem(self.listwidget)
            try:
                item.pid = pi
                item.pname = psutil.Process(pi).name()
                item.setText(str(pi) + ' - ' + psutil.Process(pi).name())
            except:
                item.setText(str(pi))

        self.listwidget.itemDoubleClicked.connect(self.listwidget.itemclick)



class MainWindow(QDialog, maingui.Ui_mainwindow):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)

        # 버튼 이벤트 핸들러
        self.scanbtn.clicked.connect(self.scanBtnClk)
        self.nextscanbtn.clicked.connect(self.nextscanBtnClk)
        self.popenbtn.clicked.connect(self.popenBtnClk)
        self.t = threading.Thread(target=self.refreshSearchTable, args=([self.searchtablewidget]))
        self.t.start()

    @staticmethod
    def refreshSearchTable(tablewidget):
        while True:
            allRows = tablewidget.rowCount()
            if hack and allRows:
                for row in range(allRows):
                    if tablewidget.rowCount() != allRows: break
                    adr = tablewidget.item(row, 0)
                    adr = int('0x'+str(adr.text()),0)
                    data,label = hack.read(adr, 4)
                    ba = bytearray(data)
                    tablewidget.setItem(row,1, QTableWidgetItem(str(sum([(256 ** i) * ba[i] for i in range(len(ba))]))))
            time.sleep(1)





    def scanBtnClk(self):
        if hack == None:  return
        text = str(self.searchtext.toPlainText())
        if text.strip() == '': return
        #self.searchlistwidget.clear()

        if valuetype == 'byte':
            num = memprc.d2h(int(text), 1)
        if valuetype == '2byte':
            num = memprc.d2h(int(text), 2)
        if valuetype == '4bytes':
            num = memprc.d2h(int(text), 4)
        if valuetype == '8bytes':
            num = memprc.d2h(int(text), 8)
        if valuetype == 'String':
            pass
            # num = memprc.d2h(int(text), 4)

        result = hack.hwnd.search_hexa(num, hack.base_address, hack.last_address)
        datalist = []
        for address, data in result:
            ba = bytearray(data)
            datalist.append((address,sum([(256**i)*ba[i] for i in range(len(ba))])))
        self.searchtablewidget.setRowCount(len(datalist))
        for i in range(len(datalist)):
            self.searchtablewidget.setItem(i, 0, QTableWidgetItem('%016X'%datalist[i][0]))
            self.searchtablewidget.setItem(i, 1, QTableWidgetItem(str(datalist[i][1])))
            self.searchtablewidget.setItem(i, 2, QTableWidgetItem(str(datalist[i][1])))
        self.searchcntlabel.setText(str(len(datalist)))



    def nextscanBtnClk(self):
        print 2

    def popenBtnClk(self):
        pod = popenDialog()
        pod.exec_()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    maindlg = MainWindow()
    maindlg.show()
    app.exec_()
