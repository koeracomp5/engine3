# -*- coding: utf-8 -*-
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


#global variables
openpname = None
scantype = 'Exact Value'
valuetype = '4bytes'
hack = None



'''
class searchTable(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self)
        self.table = QTableWidget(parent)
        self._mainwin = parent
        self.__make_table()


    def __make_table(self):
        # self.table.setSelectionBehavior(QTableView.SelectRows)
        # multiple row 선택 가능
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        # row, column 갯수 설정해야만 tablewidget 사용할수있다.


        self.table.setColumnCount(2)
        self.table.setRowCount(3)

        # column header 명 설정.
        self.table.setHorizontalHeaderLabels(["pid", "pname"])
        self.table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignRight) # header 정렬 방식


        for pi in range(0):
            self.table.setItem(pi, 0, QTableWidgetItem(''))
            self.table.setItem(pi, 1, QTableWidgetItem(''))

        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)


        #self.table.setCellWidget(1, 3, item_widget)
        #self.table.cellClicked.connect(self.__mycell_clicked)
        #mycom.currentTextChanged.connect(self.__mycom_text_changed)
'''

class myListWidget(QListWidget):
    def itemclick(self, item):
        global maindlg
        global hack
        print(item.pid,item.pname)
        hack = memprc.Hack(item.pname)
        maindlg.pnamelabel.setText(item.text())
        self.parentWidget().close()



class popenDialog(QDialog):
    def __init__(self):
        QDialog.__init__(self)
        self.setFixedSize(255,190)
        self.setWindowTitle("select prc")
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

        ''''#self.listwidget.itemDoubleClicked.connect
        #self.setLayout(QVBoxLayout())
        #self.twidget = MyTable(self)
        #self.twidget.setGeometry(QtCore.QRect(0, 0, 200, 200))
        #self.addWidget(self.textEdit)
        #self.widget'''


class MainWindow(QDialog, maingui.Ui_mainwindow):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)

        # 버튼 이벤트 핸들러
        self.scanbtn.clicked.connect(self.scanBtnClk)
        self.nextscanbtn.clicked.connect(self.nextscanBtnClk)
        self.popenbtn.clicked.connect(self.popenBtnClk)

    def scanBtnClk(self):
        if hack == None:  return
        text = str(self.searchtext.toPlainText())
        if text.strip() == '': return
        self.searchlistwidget.clear()

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
            #num = memprc.d2h(int(text), 4)

        result = hack.hwnd.search_hexa(num, hack.base_address, hack.last_address)

        cnt = 0
        for address, data in result:
            item = QtGui.QListWidgetItem(self.searchlistwidget)
            item.setText(HexDump.hexblock(data, address=address))
            #print HexDump.hexblock(data, address=address)
            cnt += 1
        self.searchcntlabel.setText(str(cnt))




    def nextscanBtnClk(self):
        print 2

    def popenBtnClk(self):
        pod = popenDialog()

        pod.exec_()






app = QApplication(sys.argv)
maindlg = MainWindow()
maindlg.show()
app.exec_()