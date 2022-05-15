#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "CPUView.h"
#include "MAPView.h"
#include "iostream"
#include <QSplitter>
#include <QTcpSocket>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <qdebug.h>
#include <qglobal.h>
#include <string>
#include <type_traits>

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
    auto data = socketClient_->readAll();
    auto total_n = data.length();
    qDebug() << "recive socket handle!! len: " << total_n;
    if (total_n == 0)
    {
        return;
    }
    auto handle_n = 0;
    while (handle_n < total_n)
    {
        switch (data[handle_n])
        {
        case MSG_REGS:
            memcpy(&mRegs, data.data() + 1, sizeof(pt_regs));
            regsView->setRegs(mRegs);
            regsView->setDebugFlag(true);
            regsView->viewport()->update();
            handle_n = handle_n + 1 + sizeof(pt_regs);
            break;
        case MSG_CPU:
            disassView->setStartAddr(*(uint32_t *)(data.data() + handle_n + 1));
            memcpy(disassView->data, data.data() + handle_n + 5, 0x400);
            disassView->setDebugFlag(true);
            disassView->setCurrentPc(mRegs.pc);
            disassView->disassInstr();
            disassView->viewport()->update();
            handle_n += 0x406;
            break;
        default:
            qDebug() << "no handle msg " << data[0];
            return;
        }
    }

    // auto handle_len = 0;
    // while (handle_len + 20 < recive_total)
    // {
    //     auto tag = std::string(data.data() + handle_len, 10);
    //     auto len = std::string(data.data() + handle_len + 10, 10);
    //     std::cout << "tag: " << tag << " len: " << len << std::endl;
    //     auto body_p = (uint8_t *)data.data() + handle_len + 20;

    //     if (strcmp(tag.data(), "regs") == 0)
    //     {
    //         memcpy(&mRegs, body_p, sizeof(pt_regs));
    //         regsView->setRegs(mRegs);
    //         regsView->setDebugFlag(true);
    //         regsView->viewport()->update();
    //     }
    //     else if (strcmp(tag.data(), "cpu") == 0)
    //     {
    //         updateDissView(body_p);
    //     }
    //     else if (strcmp(tag.data(), "maps") == 0)
    //     {
    //         auto maps = QString::fromStdString(std::string((char *)body_p, std::stoi(len)));
    //         mapView->setMap(maps);
    //     }
    //     else if (strcmp(tag.data(), "stack") == 0)
    //     {
    //         memcpy(stackView->data, body_p, 0x3000);
    //         stackView->setDebugFlag(true);
    //         stackView->setSpValue(mRegs.sp);
    //         stackView->setStartAddr(mRegs.sp & ~0xfff - 0x1000);
    //         stackView->viewport()->update();
    //     }
    //     handle_len += 20;
    //     handle_len += std::stoi(len);
    // }
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
void MainWindow::updateDissView(uint8_t *addr)
{
    memcpy(disassView->data, addr, 0x3000);
    disassView->setDebugFlag(true);
    disassView->setCurrentPc(mRegs.pc);
    disassView->disassInstr();
    disassView->viewport()->update();

    memcpy(dumpView->data, addr, 0x3000);
    dumpView->setDebugFlag(true);
    dumpView->setStartAddr(mRegs.pc & ~0xfff - 0x1000);
    dumpView->viewport()->update();
}
