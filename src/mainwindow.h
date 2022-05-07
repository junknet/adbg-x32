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

  private:
    void updateDissView(uint8_t *addr);

  private:
    Ui::MainWindow *ui;
    QTcpSocket *socketClient_;
    pt_regs mRegs;
    DisassView *disassView;
    DumpView *dumpView;
    RegsView *regsView;
    MapView *mapView;
    StackView *stackView;
};
#endif // MAINWINDOW_H
