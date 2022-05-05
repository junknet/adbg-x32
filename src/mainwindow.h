#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "CPUView.h"
#include <QListView>
#include <QMainWindow>
#include <QTcpSocket>
#include <cstdint>
#include <qglobal.h>
#include <qlistview.h>
#include <qtcpsocket.h>

struct pt_regs
{
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    uint32_t r11;
    uint32_t r12;
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
    uint32_t cpsr;
    uint32_t orig_r0;
};

QT_BEGIN_NAMESPACE
namespace Ui
{
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

  public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

  private slots:
    void on_tabWidget_tabBarClicked(int index);

  private slots:
    void on_actionopen_triggered();

    void on_actioncontinue_triggered();

    void on_actionstop_triggered();

    void on_actionmaps_triggered();

    void on_actionregs_triggered();

    void on_actionclose_triggered();

    void socketHandle();

  private:
    void updateDissView(uint8_t *addr);

  private:
    Ui::MainWindow *ui;
    QTcpSocket *socketClient_;
    DisassView *disassView;
    DumpView *dumpView;
    pt_regs mRegs;
};
#endif // MAINWINDOW_H
