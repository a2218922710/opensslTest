#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "ukey/at_digitalcertificate.h"

#include <QFileDialog>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    QString pfxFile = QFileDialog::getOpenFileName();
    if(pfxFile.isEmpty())
        return;

    //就瞎起个名字哈
    Adapts::UKey::SW_DigitalCertificate tmpParser;
    tmpParser.VerifyCertificate(pfxFile, "12345678"); //这个密码只是我的证书的密码，需要改一下
}

