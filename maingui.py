# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt4 UI code generator 4.11.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_mainwindow(object):
    def setupUi(self, mainwindow):

        mainwindow.setObjectName(_fromUtf8("mainwindow"))
        mainwindow.resize(800, 600)
        self.centralwidget = QtGui.QWidget(mainwindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))

        self.popenbtn = QtGui.QPushButton(self.centralwidget)
        self.popenbtn.setGeometry(QtCore.QRect(0, 0, 75, 23))
        self.popenbtn.setObjectName(_fromUtf8("popenbtn"))

        self.scanbtn = QtGui.QPushButton(self.centralwidget)
        self.scanbtn.setGeometry(QtCore.QRect(330, 80, 75, 23))
        self.scanbtn.setObjectName(_fromUtf8("scanbtn"))


        self.nextscanbtn = QtGui.QPushButton(self.centralwidget)
        self.nextscanbtn.setGeometry(QtCore.QRect(420, 80, 75, 23))
        self.nextscanbtn.setObjectName(_fromUtf8("nestscanbtn"))

        self.searchtext = QtGui.QTextEdit(self.centralwidget)
        self.searchtext.setGeometry(QtCore.QRect(330, 110, 331, 31))
        self.searchtext.setObjectName(_fromUtf8("serchtext"))

        self.comboBox = QtGui.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(400, 150, 91, 21))
        self.comboBox.setObjectName(_fromUtf8("comboBox"))
        self.comboBox_2 = QtGui.QComboBox(self.centralwidget)
        self.comboBox_2.setGeometry(QtCore.QRect(400, 180, 91, 21))
        self.comboBox_2.setObjectName(_fromUtf8("comboBox_2"))
        self.selectscroll = QtGui.QScrollArea(self.centralwidget)
        self.selectscroll.setGeometry(QtCore.QRect(0, 340, 801, 221))
        self.selectscroll.setWidgetResizable(True)
        self.selectscroll.setObjectName(_fromUtf8("selectscroll"))

        self.searchlistwidget = QtGui.QListWidget(self)
        self.searchlistwidget.setGeometry(QtCore.QRect(10, 60, 300, 271))
        self.searchlistwidget.setObjectName(_fromUtf8("searchlistwidget"))





        self.label = QtGui.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(330, 150, 56, 12))
        self.label.setObjectName(_fromUtf8("label"))
        self.label_2 = QtGui.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(330, 180, 61, 16))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.label_3 = QtGui.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(20, 30, 56, 12))
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.searchcntlabel = QtGui.QLabel(self.centralwidget)
        self.searchcntlabel.setGeometry(QtCore.QRect(60, 30, 56, 12))
        self.searchcntlabel.setObjectName(_fromUtf8("label_4"))

        self.pnamelabel = QtGui.QLabel(self.centralwidget)
        self.pnamelabel.setGeometry(QtCore.QRect(350, 30, 500, 12))
        self.pnamelabel.setObjectName(_fromUtf8("pnamelabel"))

        #mainwindow.setMenuBar(self.menubar)

        self.statusbar = QtGui.QStatusBar(mainwindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        #mainwindow.setStatusBar(self.statusbar)

        #self.menubar.addAction(self.menuProcess.menuAction())

        self.retranslateUi(mainwindow)
        QtCore.QMetaObject.connectSlotsByName(mainwindow)

    def retranslateUi(self, mainwindow):
        mainwindow.setWindowTitle(_translate("mainwindow", "MainWindow", None))
        self.scanbtn.setText(_translate("mainwindow", "scan", None))
        self.nextscanbtn.setText(_translate("mainwindow", "nextscan", None))
        self.popenbtn.setText(_translate("mainwindow", "popen", None))

        self.label.setText(_translate("mainwindow", "scan type", None))
        self.label_2.setText(_translate("mainwindow", "value type", None))
        self.label_3.setText(_translate("mainwindow", "found", None))
        self.searchcntlabel.setText(_translate("mainwindow", "0", None))
        self.pnamelabel.setText(_translate("mainwindow", "pname", None))

