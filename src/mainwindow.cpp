#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "CPUView.h"
#include "MAPView.h"
#include <QShortcut>
#include <QSplitter>
#include <QTcpSocket>
#include <qdebug.h>
#include <qobjectdefs.h>
#include <qshortcut.h>
#include <string>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    resize(1000, 800);
    socketClient_ = new QTcpSocket;
    disassView = new DisassView;
    disassView->socketClient_ = socketClient_;
    dumpView = new DumpView;
    regsView = new RegsView;
    mapView = new MapView;
    stackView = new StackView;

    auto splitter_middle = new QSplitter(Qt::Orientation::Vertical);
    auto splitter_top = new QSplitter(Qt::Orientation::Horizontal);
    auto splitter_bottom = new QSplitter(Qt::Orientation::Horizontal);

    ui->cpu_layout->addWidget(splitter_middle);
    splitter_middle->addWidget(splitter_top);
    splitter_middle->addWidget(splitter_bottom);
    splitter_middle->setStretchFactor(0, 8);
    splitter_middle->setStretchFactor(1, 2);

    splitter_top->addWidget(disassView);
    splitter_top->addWidget(regsView);
    splitter_top->setStretchFactor(0, 10);
    splitter_top->setStretchFactor(1, 4);

    splitter_bottom->addWidget(dumpView);
    splitter_bottom->addWidget(stackView);
    splitter_bottom->setStretchFactor(0, 10);
    splitter_bottom->setStretchFactor(1, 4);

    ui->map_layout->addWidget(mapView);

    ui->tabWidget->setCurrentIndex(0);

    QShortcut *step_button = new QShortcut(this);
    step_button->setKey(tr("f2"));
    step_button->setAutoRepeat(false);
    connect(step_button, SIGNAL(activated()), this, SLOT(send_step()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionopen_triggered()
{
    socketClient_->connectToHost("127.0.0.1", 3322);
    if (!socketClient_->waitForConnected(30000))
    {
        qDebug() << "errr";
        return;
    }
    //  set debug target process name
    socketClient_->write("com.example.jnitest");

    connect(socketClient_, SIGNAL(readyRead()), this, SLOT(socketHandle()));
    connect(socketClient_, SIGNAL(disconnected()), this, SLOT(socketClose()));
}

void MainWindow::on_actioncontinue_triggered()
{
    msgBuff_[0] = MSG_CONTINUE;
    socketClient_->write(msgBuff_, 1);
}

void MainWindow::on_actionstop_triggered()
{
    msgBuff_[0] = MSG_STOP;
    socketClient_->write(msgBuff_, 1);
}

void MainWindow::on_actionmaps_triggered()
{
    socketClient_->write("cpu_all");
}

void MainWindow::on_actionclose_triggered()
{
    socketClient_->close();
}

void MainWindow::send_step()
{
    qDebug() << "command step";
    msgBuff_[0] = MSG_STEP;
    socketClient_->write(msgBuff_, 1);
}

void MainWindow::on_actionregs_triggered()
{
}

void MainWindow::on_tabWidget_tabBarClicked(int index)
{
    switch (index)
    {
    case 1:
        socketClient_->write("maps");
        break;
    default:
        break;
    }
}

void MainWindow::socketHandle()
{
    uint8_t msg;
    QByteArray data;
    while ((msg = getMsg()))
    {
        switch (msg)
        {
        case MSG_REGS:
            data = getDataN(sizeof(pt_regs));
            memcpy(&mRegs, data.data(), sizeof(pt_regs));
            regsView->setRegs(mRegs);
            regsView->setDebugFlag(true);
            regsView->viewport()->update();

            disassView->setCurrentPc(mRegs.pc);
            disassView->setCurrentCPSR(mRegs.cpsr);
            disassView->viewport()->update();
            break;
        case MSG_CPU:
            disassView->setStartAddr(getData4());
            data = getDataN(0x400);
            memcpy(disassView->data, data.data(), 0x400);
            disassView->setDebugFlag(true);
            disassView->disassInstr();
            disassView->viewport()->update();
            break;
        case MSG_MAPS: {
            data = getDataN(getData4());
            auto map_str = QString(data);
            mapView->setMap(map_str);
            break;
        }
        default:
            qDebug() << "no handle msg : " << msg;
            return;
        }
    }
}

void MainWindow::socketClose()
{
    // clear all cpuview
    disassView->setDebugFlag(false);
    disassView->viewport()->update();
    dumpView->setDebugFlag(false);
    dumpView->viewport()->update();
    regsView->setDebugFlag(false);
    regsView->viewport()->update();
    stackView->setDebugFlag(false);
    stackView->viewport()->update();
}

uint8_t MainWindow::getMsg()
{
    auto data = socketClient_->read(1);
    if (data.length() == 0)
    {
        return 0;
    }
    else
    {
        return data[0];
    }
}

uint32_t MainWindow::getData4()
{
    auto data = socketClient_->read(4);
    return *(uint32_t *)data.data();
}

QByteArray MainWindow::getDataN(int n)
{

    auto recive_len = 0;
    QByteArray data;
    while (true)
    {
        data.append(socketClient_->read(n - data.length()));
        if (data.length() == n)
        {
            return data;
        }
        socketClient_->waitForReadyRead();
    }
}
