#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "CPUView.h"
#include "MAPView.h"
#include <QListView>
#include <QMainWindow>
#include <QTcpSocket>
#include <cstdint>
#include <qglobal.h>
#include <qlistview.h>
#include <qtcpsocket.h>

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

    void socketClose();

    void msg_cpu_slot(uint32_t addr);

    void msg_step_slot();
    void msg_add_bp_slot();
    void msg_del_bp_slot();

  private:
    uint8_t getMsg();
    uint32_t getData4();
    QByteArray getDataN(int n);

  private:
    Ui::MainWindow *ui;
    QTcpSocket *socketClient_;
    pt_regs mRegs;
    DisassView *disassView;
    DumpView *dumpView;
    RegsView *regsView;
    MapView *mapView;
    StackView *stackView;
    char msgBuff_[5];
};
#endif // MAINWINDOW_H
